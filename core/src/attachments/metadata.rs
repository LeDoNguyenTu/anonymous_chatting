//! Client-side metadata stripping (SPEC §7.1 step 2): EXIF, GPS, device
//! make and model, capture timestamps, and editing history, all removed by
//! deleting entire metadata-carrying segments and chunks through
//! `img-parts`'s structured container API — never by hand-parsing EXIF
//! (D-038).
//!
//! Scoped to JPEG, PNG, and WebP. Video is explicitly out of scope for this
//! phase; see D-038 for why.

use img_parts::jpeg::{markers, Jpeg};
use img_parts::png::Png;
use img_parts::webp::{self, WebP};
use img_parts::{Bytes, ImageEXIF, ImageICC};

use super::AttachmentError;

/// A container format this build can strip metadata from and therefore is
/// willing to send as an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// A JPEG/JFIF or EXIF-JPEG file.
    Jpeg,
    /// A PNG file.
    Png,
    /// A WebP file (VP8, VP8L, or VP8X).
    WebP,
}

impl ImageFormat {
    /// The name shown in the attachment preview manifest (SPEC §6.7.8) and
    /// the mime type recorded alongside a received attachment.
    pub fn label(self) -> &'static str {
        match self {
            ImageFormat::Jpeg => "JPEG",
            ImageFormat::Png => "PNG",
            ImageFormat::WebP => "WebP",
        }
    }
}

/// Detects the container format from its file signature.
///
/// `None` means "not a format this build strips metadata from" — the caller
/// must refuse the file rather than send it with its metadata intact. This
/// is a signature check only, the same kind `img-parts` itself performs
/// before parsing; it is not the "do not hand-parse EXIF" line, which is
/// about the metadata payload, not the container magic bytes.
pub fn detect(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.len() > 4 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        Some(ImageFormat::Jpeg)
    } else if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        Some(ImageFormat::Png)
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(ImageFormat::WebP)
    } else {
        None
    }
}

/// What stripping actually found and removed.
///
/// The attachment preview screen (SPEC §6.7.8) shows a manifest of what was
/// removed, and per SPEC §8.6's manifest rule, that has to be what actually
/// happened rather than an assumption baked into the copy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StripReport {
    /// Whether an EXIF segment/chunk was present and removed.
    pub exif_removed: bool,
    /// Whether an ICC colour profile was present and removed.
    pub icc_removed: bool,
    /// XMP, comments, thumbnails, and any other application-specific segment
    /// or chunk beyond EXIF/ICC — GPS, device make/model, capture timestamps,
    /// and editing history can all live in these too, so the whole category
    /// is removed rather than only the two img-parts names a convenience
    /// method for.
    pub other_metadata_removed: bool,
}

/// Strips every metadata-carrying segment or chunk from an image, leaving
/// only what is needed to decode the pixels.
pub fn strip(bytes: &[u8], format: ImageFormat) -> Result<(Vec<u8>, StripReport), AttachmentError> {
    let input = Bytes::copy_from_slice(bytes);
    let mut report = StripReport::default();

    let out = match format {
        ImageFormat::Jpeg => {
            let mut jpeg = Jpeg::from_bytes(input).map_err(|_| AttachmentError::Malformed)?;
            report.exif_removed = jpeg.exif().is_some();
            report.icc_removed = jpeg.icc_profile().is_some();
            jpeg.set_exif(None);
            jpeg.set_icc_profile(None);

            // Every remaining application segment (JFIF thumbnails, XMP,
            // Photoshop IRB, anything else a camera or editor wrote) and
            // every comment. Structural segments — SOF, DHT, DQT, SOS, the
            // entropy-coded scan, restart markers — are untouched; they are
            // what actually decodes the image, and none of them carry EXIF,
            // GPS, or authorship metadata.
            let mut removed_other = false;
            for marker in markers::APP0..=markers::APP15 {
                if jpeg.segment_by_marker(marker).is_some() {
                    removed_other = true;
                }
                jpeg.remove_segments_by_marker(marker);
            }
            if jpeg.segment_by_marker(markers::COM).is_some() {
                removed_other = true;
            }
            jpeg.remove_segments_by_marker(markers::COM);
            report.other_metadata_removed = removed_other;

            jpeg.encoder().bytes().to_vec()
        }
        ImageFormat::Png => {
            let mut png = Png::from_bytes(input).map_err(|_| AttachmentError::Malformed)?;
            report.exif_removed = png.exif().is_some();
            report.icc_removed = png.icc_profile().is_some();
            png.set_exif(None);
            png.set_icc_profile(None);

            // tEXt/zTXt/iTXt carry free-form text — author, software, and
            // sometimes an embedded XMP block with GPS or editing history.
            // tIME carries the last-modified timestamp. None of the four are
            // needed to decode the pixels.
            let mut removed_other = false;
            for kind in [*b"tEXt", *b"zTXt", *b"iTXt", *b"tIME"] {
                if png.chunk_by_type(kind).is_some() {
                    removed_other = true;
                }
                png.remove_chunks_by_type(kind);
            }
            report.other_metadata_removed = removed_other;

            png.encoder().bytes().to_vec()
        }
        ImageFormat::WebP => {
            let mut webp = WebP::from_bytes(input).map_err(|_| AttachmentError::Malformed)?;
            report.exif_removed = webp.exif().is_some();
            report.icc_removed = webp.icc_profile().is_some();
            webp.set_exif(None);
            webp.set_icc_profile(None);

            let had_xmp = webp.has_chunk(webp::CHUNK_XMP);
            webp.remove_chunks_by_id(webp::CHUNK_XMP);
            report.other_metadata_removed = had_xmp;

            webp.encoder().bytes().to_vec()
        }
    };

    Ok((out, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal JPEG carrying a real EXIF segment with a GPS IFD, built by
    /// hand from the marker structure rather than sourced from a real photo —
    /// small, deterministic, and enough to exercise stripping without a test
    /// fixture binary in the repository.
    fn jpeg_with_exif_and_gps() -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI

        // APP1/EXIF: "Exif\0\0" + a TIFF header with one GPS-tag-shaped byte
        // string. This does not have to be a byte-perfect IFD — stripping
        // removes the whole segment unconditionally, it never parses the
        // IFD, so the test only needs `jpeg.exif()` to recognise it as EXIF.
        let mut exif_payload = b"Exif\0\0".to_vec();
        exif_payload.extend_from_slice(b"II*\0"); // little-endian TIFF header
        exif_payload.extend_from_slice(b"GPS 37.7749 N 122.4194 W Canon EOS 5D");
        push_segment(&mut out, 0xE1, &exif_payload);

        // A comment segment, which is not EXIF/ICC but is still metadata.
        push_segment(&mut out, 0xFE, b"edited in a photo tool");

        // Minimal structure so this still resembles a real JPEG shape. This
        // build never has to *decode* it, only carry it through stripping.
        push_segment(&mut out, 0xDB, &[0u8; 3]); // DQT, arbitrary contents
        push_segment(&mut out, 0xC0, &[8, 0, 1, 0, 1, 1, 0, 0, 0]); // SOF0
        push_segment(&mut out, 0xC4, &[0u8; 3]); // DHT

        // SOS carries entropy-coded data after its header, ended by EOI.
        out.push(0xFF);
        out.push(0xDA);
        let sos_header: &[u8] = &[0, 0]; // placeholder length body
        out.extend_from_slice(&((sos_header.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(sos_header);
        out.extend_from_slice(&[0xAB, 0xCD]); // "entropy-coded" scan data
        out.push(0xFF);
        out.push(0xD9); // EOI

        out
    }

    fn push_segment(out: &mut Vec<u8>, marker: u8, contents: &[u8]) {
        out.push(0xFF);
        out.push(marker);
        out.extend_from_slice(&((contents.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(contents);
    }

    #[test]
    fn detects_jpeg_png_and_webp_by_signature() {
        assert_eq!(detect(&jpeg_with_exif_and_gps()), Some(ImageFormat::Jpeg));

        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert_eq!(detect(&png), Some(ImageFormat::Png));

        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&4u32.to_le_bytes());
        webp.extend_from_slice(b"WEBP");
        webp.extend_from_slice(b"VP8 "); // a real file always has a sub-chunk
        assert_eq!(detect(&webp), Some(ImageFormat::WebP));
    }

    #[test]
    fn an_unrecognised_file_is_not_detected_as_an_image() {
        assert_eq!(detect(b"not an image, just text"), None);
        assert_eq!(detect(&[0u8; 2]), None);
    }

    #[test]
    fn jpeg_gps_and_exif_and_comments_are_all_removed() {
        let original = jpeg_with_exif_and_gps();
        let (stripped, report) = strip(&original, ImageFormat::Jpeg).expect("strips");

        assert!(report.exif_removed);
        assert!(report.other_metadata_removed);

        // The actual property SPEC §8.4 tests: the distinctive strings this
        // file's EXIF/comment carried must not survive in any form.
        for needle in [
            "GPS 37.7749",
            "122.4194",
            "Canon EOS 5D",
            "edited in a photo tool",
        ] {
            assert!(
                !contains_bytes(&stripped, needle.as_bytes()),
                "{needle:?} survived stripping"
            );
        }
    }

    #[test]
    fn stripping_reports_nothing_removed_when_there_was_nothing_to_remove() {
        // A JPEG with no EXIF, no ICC, and no comment segment — stripping
        // must not claim to have removed metadata that was never there.
        let mut out = vec![0xFF, 0xD8];
        push_segment(&mut out, 0xDB, &[0u8; 3]);
        push_segment(&mut out, 0xC0, &[8, 0, 1, 0, 1, 1, 0, 0, 0]);
        push_segment(&mut out, 0xC4, &[0u8; 3]);
        out.extend_from_slice(&[0xFF, 0xDA, 0, 4, 0, 0, 0xAB, 0xCD, 0xFF, 0xD9]);

        let (_, report) = strip(&out, ImageFormat::Jpeg).expect("strips");
        assert!(!report.exif_removed);
        assert!(!report.icc_removed);
        assert!(!report.other_metadata_removed);
    }

    #[test]
    fn a_malformed_file_is_reported_rather_than_panicking() {
        assert!(matches!(
            strip(&[0xFF, 0xD8, 0xFF], ImageFormat::Jpeg),
            Err(AttachmentError::Malformed)
        ));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len().max(1))
            .any(|window| window == needle)
    }
}
