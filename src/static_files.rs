use std::{
    fs::{File, Metadata},
    io,
    ops::Range,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::stream;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode,
    header::{
        ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_MATCH,
        IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED, LOCATION,
        RANGE,
    },
    request::Parts,
};
use http_body::Frame;
use http_body_util::StreamBody;
use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
use sha2::{Digest, Sha256};
use tokio::{sync::Semaphore, task::spawn_blocking};

use crate::body::{self, Body};

const CONTAINMENT: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

pub struct DocumentRoot {
    root: Arc<OwnedFd>,
    index: Option<Arc<str>>,
    file_work: Arc<Semaphore>,
    max_buffer_bytes: usize,
}

impl DocumentRoot {
    pub fn open(
        root: &Path,
        index: Option<&str>,
        file_work: Arc<Semaphore>,
        max_buffer_bytes: usize,
    ) -> Result<Self> {
        ensure!(max_buffer_bytes > 0, "file read size must be positive");
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let root = open(root, flags, Mode::empty())
            .with_context(|| format!("opening document root {}", root.display()))?;
        openat2(&root, ".", flags, Mode::empty(), CONTAINMENT)
            .context("checking openat2 support for document root")?;
        Ok(Self {
            root: Arc::new(root),
            index: index.map(Arc::from),
            file_work,
            max_buffer_bytes,
        })
    }

    pub async fn serve(&self, request: Parts, relative_path: &str) -> Response<Body> {
        if request.method != Method::GET && request.method != Method::HEAD {
            let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            return response;
        }

        let Some(path) = decode_relative_path(relative_path) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        let Ok(permit) = self.file_work.clone().acquire_owned().await else {
            return empty_response(StatusCode::SERVICE_UNAVAILABLE);
        };
        let root = self.root.clone();
        let index = self.index.clone();
        let trailing_slash = request.uri.path().ends_with('/');
        let selection = spawn_blocking(move || {
            let _permit = permit;
            select_file(&root, &path, index.as_deref(), trailing_slash)
        })
        .await;
        match selection {
            Ok(Ok(Selection::File(document))) => self.file_response(request, document),
            Ok(Ok(Selection::Directory)) => redirect_directory(request),
            Ok(Err(_)) => empty_response(StatusCode::NOT_FOUND),
            Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    fn file_response(&self, request: Parts, document: Document) -> Response<Body> {
        let length = document.length;
        let modified = document.modified;
        let mut response = empty_response(StatusCode::OK);
        let headers = response.headers_mut();
        headers.insert(ETAG, value(&document.etag));
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Some(modified) = modified {
            headers.insert(LAST_MODIFIED, value(&httpdate::fmt_http_date(modified)));
        }
        if let Some(status) = precondition_status(&request.headers, &document.etag, modified) {
            *response.status_mut() = status;
            return response;
        }

        let range = if request.method == Method::GET {
            select_range(&request.headers, length)
        } else {
            ByteRange::Full
        };
        let range = match range {
            ByteRange::Full => 0..length,
            ByteRange::Partial(range) => {
                response.headers_mut().insert(
                    CONTENT_RANGE,
                    value(&format!("bytes {}-{}/{length}", range.start, range.end - 1)),
                );
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                range
            }
            ByteRange::Unsatisfiable => {
                response
                    .headers_mut()
                    .insert(CONTENT_RANGE, value(&format!("bytes */{length}")));
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                return response;
            }
        };
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(range.end - range.start));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, value(document.content_type.as_ref()));
        if request.method == Method::GET && !range.is_empty() {
            *response.body_mut() = file_body(
                document.file,
                range,
                self.file_work.clone(),
                self.max_buffer_bytes,
            );
        }
        response
    }
}

struct Document {
    file: File,
    length: u64,
    etag: String,
    modified: Option<SystemTime>,
    content_type: mime_guess::Mime,
}

enum Selection {
    File(Document),
    Directory,
}

fn select_file(
    root: &OwnedFd,
    path: &Path,
    index: Option<&str>,
    trailing_slash: bool,
) -> io::Result<Selection> {
    let file = open_file(root, path)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        if !trailing_slash {
            return Ok(Selection::Directory);
        }
        let index = index.ok_or(io::ErrorKind::NotFound)?;
        let path = path.join(index);
        // Resolve the index beneath the root again, including during a directory rename.
        let file = open_file(root, &path)?;
        let metadata = file.metadata()?;
        return file_selection(file, metadata, &path);
    }
    if trailing_slash {
        return Err(io::ErrorKind::NotFound.into());
    }
    file_selection(file, metadata, path)
}

fn open_file(root: impl AsFd, path: &Path) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
    openat2(root, path, flags, Mode::empty(), CONTAINMENT)
        .map(File::from)
        .map_err(Into::into)
}

fn file_selection(file: File, metadata: Metadata, path: &Path) -> io::Result<Selection> {
    if !metadata.is_file() {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(Selection::File(Document {
        file,
        length: metadata.len(),
        etag: weak_etag(&metadata),
        modified: last_modified(&metadata),
        content_type: mime_guess::from_path(path).first_or_octet_stream(),
    }))
}

fn decode_relative_path(path: &str) -> Option<PathBuf> {
    if path.is_empty() {
        return Some(PathBuf::from("."));
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    let mut relative = PathBuf::new();
    for segment in path.split('/') {
        let decoded = percent_encoding::percent_decode_str(segment).collect::<Vec<_>>();
        if decoded.is_empty()
            || matches!(decoded.as_slice(), b"." | b"..")
            || decoded.iter().any(|byte| matches!(byte, b'/' | b'\\' | 0))
        {
            return None;
        }
        relative.push(std::ffi::OsStr::from_bytes(&decoded));
    }
    Some(relative)
}

fn file_body(
    file: File,
    range: Range<u64>,
    file_work: Arc<Semaphore>,
    max_buffer_bytes: usize,
) -> Body {
    let file = Arc::new(file);
    let stream = stream::try_unfold(range, move |mut remaining| {
        let file = file.clone();
        let file_work = file_work.clone();
        async move {
            if remaining.is_empty() {
                return Ok::<_, io::Error>(None);
            }
            let size = (remaining.end - remaining.start).min(max_buffer_bytes as u64) as usize;
            let offset = remaining.start;
            let permit = file_work.acquire_owned().await.map_err(io::Error::other)?;
            let bytes = spawn_blocking(move || {
                let _permit = permit;
                let mut buffer = vec![0; size];
                file.read_exact_at(&mut buffer, offset)?;
                Ok::<_, io::Error>(Bytes::from(buffer))
            })
            .await
            .map_err(io::Error::other)??;
            remaining.start += size as u64;
            Ok(Some((Frame::data(bytes), remaining)))
        }
    });
    body::boxed(StreamBody::new(stream))
}

fn redirect_directory(request: Parts) -> Response<Body> {
    let mut location = request.uri.path().to_owned();
    location.push('/');
    if let Some(query) = request.uri.query() {
        location.push('?');
        location.push_str(query);
    }
    let Ok(location) = HeaderValue::from_str(&location) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    let mut response = empty_response(StatusCode::PERMANENT_REDIRECT);
    response.headers_mut().insert(LOCATION, location);
    response
}

fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(body::empty());
    *response.status_mut() = status;
    response
}

fn value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("valid generated header value")
}

fn weak_etag(metadata: &Metadata) -> String {
    let mut digest = Sha256::new();
    digest.update(metadata.dev().to_be_bytes());
    digest.update(metadata.ino().to_be_bytes());
    digest.update(metadata.len().to_be_bytes());
    digest.update(metadata.mtime().to_be_bytes());
    digest.update(metadata.mtime_nsec().to_be_bytes());
    digest.update(metadata.ctime().to_be_bytes());
    digest.update(metadata.ctime_nsec().to_be_bytes());
    format!("W/\"{:x}\"", digest.finalize())
}

fn last_modified(metadata: &Metadata) -> Option<SystemTime> {
    // HTTP dates are second resolution and cannot be later than the response's Date.
    let modified = metadata.modified().ok()?.min(SystemTime::now());
    let seconds = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    // httpdate can format dates through 9999-12-31.
    (seconds < 253_402_300_800).then(|| UNIX_EPOCH + Duration::from_secs(seconds))
}

fn precondition_status(
    headers: &HeaderMap,
    etag: &str,
    modified: Option<SystemTime>,
) -> Option<StatusCode> {
    if headers.contains_key(IF_MATCH) {
        // The weak ETag can satisfy only the wildcard under strong comparison.
        if !wildcard(headers, IF_MATCH) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let Some((modified, condition)) =
        modified.zip(header_date(headers, IF_UNMODIFIED_SINCE))
        && modified > condition
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }

    if headers.contains_key(IF_NONE_MATCH) {
        if wildcard(headers, IF_NONE_MATCH) || weak_tag_matches(headers, etag) {
            return Some(StatusCode::NOT_MODIFIED);
        }
    } else if let Some((modified, condition)) =
        modified.zip(header_date(headers, IF_MODIFIED_SINCE))
        && modified <= condition
    {
        return Some(StatusCode::NOT_MODIFIED);
    }
    None
}

fn wildcard(headers: &HeaderMap, name: HeaderName) -> bool {
    one_header(headers, name).is_some_and(|value| trim_ows(value.as_bytes()) == b"*")
}

fn weak_tag_matches(headers: &HeaderMap, etag: &str) -> bool {
    let current = &etag.as_bytes()[2..];
    let mut matched = false;
    for value in headers.get_all(IF_NONE_MATCH) {
        let mut quoted = false;
        let tags = value.as_bytes().split(|byte| {
            if *byte == b'"' {
                quoted = !quoted;
            }
            *byte == b',' && !quoted
        });
        for tag in tags.map(trim_ows).filter(|tag| !tag.is_empty()) {
            let opaque = tag.strip_prefix(b"W/").unwrap_or(tag);
            let Some(payload) = opaque
                .strip_prefix(b"\"")
                .and_then(|tag| tag.strip_suffix(b"\""))
            else {
                return false;
            };
            if !payload
                .iter()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e | 0x80..=0xff))
            {
                return false;
            }
            matched |= opaque == current;
        }
    }
    matched
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && matches!(value[start], b' ' | b'\t') {
        start += 1;
    }
    while start < end && matches!(value[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &value[start..end]
}

fn header_date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
    let value = one_header(headers, name)?.to_str().ok()?.trim();
    httpdate::parse_http_date(value).ok()
}

fn one_header(headers: &HeaderMap, name: HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).into_iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

enum ByteRange {
    Full,
    Partial(Range<u64>),
    Unsatisfiable,
}

fn select_range(headers: &HeaderMap, length: u64) -> ByteRange {
    // The weak file validators fail If-Range.
    if headers.contains_key(IF_RANGE) {
        return ByteRange::Full;
    }
    one_header(headers, RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_range(value.trim(), length))
        .unwrap_or(ByteRange::Full)
}

fn parse_range(value: &str, length: u64) -> Option<ByteRange> {
    let (unit, bounds) = value.split_once('=')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (start, end) = bounds.split_once('-')?;
    if start.is_empty() {
        let suffix_length = decimal(end)?;
        if suffix_length == 0 || length == 0 {
            return Some(ByteRange::Unsatisfiable);
        }
        return Some(ByteRange::Partial(
            length.saturating_sub(suffix_length)..length,
        ));
    }
    let start = decimal(start)?;
    let end = if end.is_empty() {
        length
    } else {
        let last = decimal(end)?;
        if last < start {
            return None;
        }
        length.min(last.saturating_add(1))
    };
    if start >= length {
        return Some(ByteRange::Unsatisfiable);
    }
    Some(ByteRange::Partial(start..end))
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.bytes().try_fold(0_u64, |number, byte| {
        byte.is_ascii_digit().then(|| {
            number
                .saturating_mul(10)
                .saturating_add(u64::from(byte - b'0'))
        })
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use http::Request;
    use http_body_util::BodyExt;
    use rustix::fs::{CWD, Mode, mkfifoat};
    use tokio::time::timeout;

    use super::*;

    fn request(method: Method, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut request = Request::builder().method(method).uri(uri);
        for &(name, value) in headers {
            request = request.header(name, value);
        }
        request.body(()).unwrap().into_parts().0
    }

    fn root(path: &Path) -> DocumentRoot {
        DocumentRoot::open(path, Some("index.html"), Arc::new(Semaphore::new(2)), 8192).unwrap()
    }

    #[tokio::test]
    async fn serves_directory_index_with_metadata_and_ranges() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("docs")).unwrap();
        fs::write(directory.path().join("docs/index.html"), "abcdef").unwrap();
        let root = root(directory.path());

        let redirect = root
            .serve(request(Method::GET, "/mounted/docs?x=1&x=2", &[]), "docs")
            .await;
        assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(redirect.headers()[LOCATION], "/mounted/docs/?x=1&x=2");

        let get = root
            .serve(request(Method::GET, "/docs/", &[]), "docs/")
            .await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()[CONTENT_TYPE], "text/html");
        assert_eq!(get.headers()[CONTENT_LENGTH], "6");
        assert_eq!(get.headers()[ACCEPT_RANGES], "bytes");
        let etag = get.headers()[ETAG].to_str().unwrap().to_string();
        let modified = get.headers()[LAST_MODIFIED].to_str().unwrap().to_string();
        assert!(etag.starts_with("W/\""));
        assert_eq!(
            get.into_body().collect().await.unwrap().to_bytes(),
            "abcdef"
        );

        let range = root
            .serve(
                request(Method::GET, "/docs/", &[("range", "bytes=2-4")]),
                "docs/",
            )
            .await;
        assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(range.headers()[CONTENT_RANGE], "bytes 2-4/6");
        assert_eq!(range.headers()[CONTENT_LENGTH], "3");
        assert_eq!(range.into_body().collect().await.unwrap().to_bytes(), "cde");

        let oversized_range = root
            .serve(
                request(
                    Method::GET,
                    "/docs/",
                    &[("range", "bytes=123456789012345678901-")],
                ),
                "docs/",
            )
            .await;
        assert_eq!(oversized_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(oversized_range.headers()[CONTENT_RANGE], "bytes */6");

        let head = root
            .serve(
                request(Method::HEAD, "/docs/", &[("range", "bytes=-2")]),
                "docs/",
            )
            .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[CONTENT_LENGTH], "6");
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );

        let conditional_headers = [
            (
                "if-none-match",
                format!("\"different,tag\", {}", &etag[2..]),
            ),
            ("if-modified-since", modified),
        ];
        for (name, value) in &conditional_headers {
            let response = root
                .serve(request(Method::GET, "/docs/", &[(name, value)]), "docs/")
                .await;
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(response.headers()[ETAG], etag);
        }

        let response = root
            .serve(
                request(Method::GET, "/docs/", &[("if-match", &etag)]),
                "docs/",
            )
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        let response = root
            .serve(
                request(
                    Method::GET,
                    "/docs/",
                    &[("range", "bytes=0-1"), ("if-range", &etag)],
                ),
                "docs/",
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = root
            .serve(request(Method::POST, "/docs/", &[]), "docs/")
            .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[ALLOW], "GET, HEAD");
    }

    #[tokio::test]
    async fn contains_file_resolution_and_decodes_segments_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        fs::create_dir(&path).unwrap();
        fs::write(directory.path().join("private.txt"), "outside").unwrap();
        symlink("../private.txt", path.join("symlink.txt")).unwrap();
        symlink("..", path.join("dir")).unwrap();
        mkfifoat(CWD, path.join("fifo"), Mode::RUSR | Mode::WUSR).unwrap();
        fs::write(path.join("a b%2F"), "once").unwrap();
        let root = root(&path);

        for path in [
            "symlink.txt",
            "dir/private.txt",
            "fifo",
            "%2E%2E/private.txt",
            "a%2fb",
            "a%00b",
        ] {
            let response = timeout(
                Duration::from_secs(2),
                root.serve(request(Method::GET, "/", &[]), path),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let response = root
            .serve(request(Method::GET, "/a%20b%252F", &[]), "a%20b%252F")
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "once"
        );
        let response = root
            .serve(request(Method::GET, "/a%20b%252F/", &[]), "a%20b%252F/")
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn streams_original_descriptor_with_bounded_reads() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("file.txt"), "old body").unwrap();
        let work = Arc::new(Semaphore::new(1));
        let root = DocumentRoot::open(directory.path(), None, work.clone(), 3).unwrap();
        let response = root
            .serve(request(Method::GET, "/file.txt", &[]), "file.txt")
            .await;
        fs::write(directory.path().join("next.txt"), "changed").unwrap();
        fs::rename(
            directory.path().join("next.txt"),
            directory.path().join("file.txt"),
        )
        .unwrap();

        let mut body = response.into_body();
        let permit = work.acquire().await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), body.frame())
                .await
                .is_err()
        );
        drop(permit);
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, "old");
        let remaining = body.collect().await.unwrap().to_bytes();
        assert_eq!(remaining, " body");

        let next = root
            .serve(request(Method::GET, "/file.txt", &[]), "file.txt")
            .await;
        assert_eq!(
            next.into_body().collect().await.unwrap().to_bytes(),
            "changed"
        );
    }
}
