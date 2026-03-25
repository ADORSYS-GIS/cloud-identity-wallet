//! CSS color value validation using [csscolorparser].
//!
//! Supports all CSS Color Module Level 4 formats including:
//! - Named colors (e.g., "red", "transparent")
//! - Hex notation (e.g., "#fff", "#ffffff", "#ffffff00")
//! - RGB/RGBA functions (e.g., "rgb(255, 0, 0)", "rgba(100%, 0%, 0%, 0.5)")
//! - HSL/HSLA functions (e.g., "hsl(0, 100%, 50%)")
//! - And more modern formats (lab, lch, oklab, oklch, hwb)
//!
//! [csscolorparser]: https://docs.rs/csscolorparser

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A validated CSS color value.
///
/// Wraps the well-tested `csscolorparser::Color` type for serialization
/// and validation in credential display metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CssColor(String);

impl CssColor {
    /// Creates a new CSS color, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, CssColorError> {
        let original = s.into();
        csscolorparser::parse(&original).map_err(|_| CssColorError {
            input: original.clone(),
        })?;
        Ok(Self(original))
    }

    /// Returns the original string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error returned when a CSS color string is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CssColorError {
    input: String,
}

impl fmt::Display for CssColorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CSS color value: {:?}", self.input)
    }
}

impl std::error::Error for CssColorError {}

impl FromStr for CssColor {
    type Err = CssColorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for CssColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CssColor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CssColor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_colors() {
        assert!(CssColor::new("#fff").is_ok());
        assert!(CssColor::new("#ffffff").is_ok());
        assert!(CssColor::new("#fff0").is_ok());
        assert!(CssColor::new("#ffffff00").is_ok());
        assert!(CssColor::new("#12107c").is_ok());
        assert!(CssColor::new("#FFFFFF").is_ok());
    }

    #[test]
    fn test_invalid_hex_colors() {
        assert!(CssColor::new("#").is_err());
        assert!(CssColor::new("#ff").is_err());
        assert!(CssColor::new("#fffff").is_err());
        assert!(CssColor::new("#gggggg").is_err());
    }

    #[test]
    fn test_named_colors() {
        assert!(CssColor::new("red").is_ok());
        assert!(CssColor::new("blue").is_ok());
        assert!(CssColor::new("transparent").is_ok());
        // Named colors are case-insensitive per CSS spec
        assert!(CssColor::new("RED").is_ok());
        assert!(CssColor::new("Blue").is_ok());
    }

    #[test]
    fn test_rgb_function() {
        assert!(CssColor::new("rgb(255, 0, 0)").is_ok());
        assert!(CssColor::new("rgb(100%, 0%, 0%)").is_ok());
        assert!(CssColor::new("rgba(255, 0, 0, 0.5)").is_ok());
        assert!(CssColor::new("rgba(255, 0, 0, 50%)").is_ok());
        // Modern space-separated syntax
        assert!(CssColor::new("rgb(255 0 0)").is_ok());
        assert!(CssColor::new("rgb(255 0 0 / 50%)").is_ok());
    }

    #[test]
    fn test_hsl_function() {
        assert!(CssColor::new("hsl(0, 100%, 50%)").is_ok());
        assert!(CssColor::new("hsl(360, 100%, 50%)").is_ok());
        assert!(CssColor::new("hsla(180, 50%, 50%, 0.5)").is_ok());
    }

    #[test]
    fn test_modern_color_formats() {
        // CSS Color Level 4 formats
        assert!(CssColor::new("lab(50% 0 0)").is_ok());
        assert!(CssColor::new("lch(50% 0 0)").is_ok());
        assert!(CssColor::new("oklab(0.5 0 0)").is_ok());
        assert!(CssColor::new("oklch(0.5 0 0)").is_ok());
        assert!(CssColor::new("hwb(0 0% 0%)").is_ok());
    }

    #[test]
    fn test_serde() {
        let color = CssColor::new("#12107c").unwrap();
        let json = serde_json::to_string(&color).unwrap();
        assert_eq!(json, "\"#12107c\"");

        let parsed: CssColor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, color);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<CssColor, _> = serde_json::from_str("\"not-a-color\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_preserves_original_format() {
        // The wrapper preserves the original string format
        let color = CssColor::new("RED").unwrap();
        assert_eq!(color.as_str(), "RED"); // Preserves case

        let color = CssColor::new("#FFF").unwrap();
        assert_eq!(color.as_str(), "#FFF"); // Preserves short form
    }
}
