use std::fs;
use std::path::Path;
use std::ffi::OsStr;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use flate2::read::{GzDecoder, DeflateDecoder};

// Handle all three cases of NVD dict (gz, zip, or decompressed xml)
pub fn decompress_or_return(cpe_dict_path: &Path) -> Result<String, std::io::Error> {
	match cpe_dict_path.extension().and_then(OsStr::to_str) {
		Some("gz") => {
			let data = fs::read(cpe_dict_path)?;
			let mut gz = GzDecoder::new(data.as_slice());
			let mut s = String::new();
			gz.read_to_string(&mut s)?;
			Ok(s)
		},
		Some("zip") => {
			let data = fs::read(cpe_dict_path)?;
			let mut deflater = DeflateDecoder::new(data.as_slice());
			let mut s = String::new();
			deflater.read_to_string(&mut s)?;
			Ok(s)
		},
		Some("xml") => {
			match fs::read_to_string(cpe_dict_path) {
				Ok(s) => Ok(s),
				Err(e) => Err(e),
			}
		},
		_ => {Err(Error::new(ErrorKind::Other, "Invalid Dictionary File Extension"))}
	}
}