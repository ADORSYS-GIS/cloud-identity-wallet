//! CSS color value validation per [CSS Color Module Level 3].
//!
//! [CSS Color Module Level 3]: https://www.w3.org/TR/css-color-3/

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A validated CSS color value (hex, named, or functional notation).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CssColor(String);

impl CssColor {
    /// Creates a new CSS color, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, CssColorError> {
        let s = s.into();
        validate_css_color(&s)?;
        Ok(Self(s))
    }

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

/// Validates a CSS color string.
fn validate_css_color(s: &str) -> Result<(), CssColorError> {
    let trimmed = s.trim();

    if trimmed.is_empty() {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Check hex notation
    if trimmed.starts_with('#') {
        validate_hex_color(trimmed)?;
        return Ok(());
    }

    // Check functional notation
    let lower = trimmed.to_lowercase();
    if lower.starts_with("rgb(") || lower.starts_with("rgba(") {
        validate_rgb_function(&lower)?;
        return Ok(());
    }
    if lower.starts_with("hsl(") || lower.starts_with("hsla(") {
        validate_hsl_function(&lower)?;
        return Ok(());
    }

    // Check named colors (case-insensitive)
    if is_valid_named_color(&lower) {
        return Ok(());
    }

    Err(CssColorError {
        input: s.to_string(),
    })
}

/// Validates hex color notation: #RGB, #RRGGBB, #RGBA, #RRGGBBAA
fn validate_hex_color(s: &str) -> Result<(), CssColorError> {
    let hex = &s[1..]; // Remove '#'

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    match hex.len() {
        3 | 4 | 6 | 8 => Ok(()),
        _ => Err(CssColorError {
            input: s.to_string(),
        }),
    }
}

/// Validates rgb()/rgba() functional notation.
fn validate_rgb_function(s: &str) -> Result<(), CssColorError> {
    // Basic validation: check it ends with ')' and has reasonable content
    if !s.ends_with(')') {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Extract content between parentheses
    let start = s.find('(').ok_or_else(|| CssColorError {
        input: s.to_string(),
    })?;
    let content = &s[start + 1..s.len() - 1];

    // Parse values - accept both comma-separated and space-separated modern syntax
    let values: Vec<&str> = if content.contains(',') {
        content.split(',').map(|v| v.trim()).collect()
    } else {
        content.split_whitespace().collect()
    };

    // Should have 3 or 4 values (RGB or RGBA)
    if values.len() < 3 || values.len() > 4 {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Validate each value
    for (i, val) in values.iter().enumerate() {
        if i < 3 {
            // R, G, B values: 0-255 or percentage
            if !is_valid_rgb_value(val) {
                return Err(CssColorError {
                    input: s.to_string(),
                });
            }
        } else {
            // Alpha value: 0-1 or percentage
            if !is_valid_alpha_value(val) {
                return Err(CssColorError {
                    input: s.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Validates hsl()/hsla() functional notation.
fn validate_hsl_function(s: &str) -> Result<(), CssColorError> {
    if !s.ends_with(')') {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    let start = s.find('(').ok_or_else(|| CssColorError {
        input: s.to_string(),
    })?;
    let content = &s[start + 1..s.len() - 1];

    // HSL uses comma-separated values
    let values: Vec<&str> = content.split(',').map(|v| v.trim()).collect();

    if values.len() < 3 || values.len() > 4 {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Hue: 0-360 or angle
    if !is_valid_hue(values[0]) {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Saturation and Lightness: percentage
    if !is_valid_percentage(values[1]) || !is_valid_percentage(values[2]) {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    // Alpha (optional)
    if values.len() == 4 && !is_valid_alpha_value(values[3]) {
        return Err(CssColorError {
            input: s.to_string(),
        });
    }

    Ok(())
}

/// Checks if a value is a valid RGB component (0-255 or percentage).
fn is_valid_rgb_value(s: &str) -> bool {
    if s.ends_with('%') {
        let num = s.trim_end_matches('%').trim();
        num.parse::<f32>().is_ok()
    } else {
        s.parse::<u8>().is_ok()
    }
}

/// Checks if a value is a valid alpha (0-1 or percentage).
fn is_valid_alpha_value(s: &str) -> bool {
    if s.ends_with('%') {
        let num = s.trim_end_matches('%').trim();
        num.parse::<f32>().is_ok()
    } else {
        s.parse::<f64>()
            .map(|v| (0.0..=1.0).contains(&v))
            .unwrap_or(false)
    }
}

/// Checks if a value is a valid hue (0-360 or angle).
fn is_valid_hue(s: &str) -> bool {
    let s = s.trim_end_matches("deg").trim();
    s.parse::<f32>()
        .map(|v| (0.0..=360.0).contains(&v))
        .unwrap_or(false)
}

/// Checks if a value is a valid percentage.
fn is_valid_percentage(s: &str) -> bool {
    s.ends_with('%') && s.trim_end_matches('%').trim().parse::<f32>().is_ok()
}

/// List of CSS3 named colors.
const CSS3_NAMED_COLORS: &[&str] = &[
    "aliceblue",
    "antiquewhite",
    "aqua",
    "aquamarine",
    "azure",
    "beige",
    "bisque",
    "black",
    "blanchedalmond",
    "blue",
    "blueviolet",
    "brown",
    "burlywood",
    "cadetblue",
    "chartreuse",
    "chocolate",
    "coral",
    "cornflowerblue",
    "cornsilk",
    "crimson",
    "cyan",
    "darkblue",
    "darkcyan",
    "darkgoldenrod",
    "darkgray",
    "darkgreen",
    "darkgrey",
    "darkkhaki",
    "darkmagenta",
    "darkolivegreen",
    "darkorange",
    "darkorchid",
    "darkred",
    "darksalmon",
    "darkseagreen",
    "darkslateblue",
    "darkslategray",
    "darkslategrey",
    "darkturquoise",
    "darkviolet",
    "deeppink",
    "deepskyblue",
    "dimgray",
    "dimgrey",
    "dodgerblue",
    "firebrick",
    "floralwhite",
    "forestgreen",
    "fuchsia",
    "gainsboro",
    "ghostwhite",
    "gold",
    "goldenrod",
    "gray",
    "green",
    "greenyellow",
    "grey",
    "honeydew",
    "hotpink",
    "indianred",
    "indigo",
    "ivory",
    "khaki",
    "lavender",
    "lavenderblush",
    "lawngreen",
    "lemonchiffon",
    "lightblue",
    "lightcoral",
    "lightcyan",
    "lightgoldenrodyellow",
    "lightgray",
    "lightgreen",
    "lightgrey",
    "lightpink",
    "lightsalmon",
    "lightseagreen",
    "lightskyblue",
    "lightslategray",
    "lightslategrey",
    "lightsteelblue",
    "lightyellow",
    "lime",
    "limegreen",
    "linen",
    "magenta",
    "maroon",
    "mediumaquamarine",
    "mediumblue",
    "mediumorchid",
    "mediumpurple",
    "mediumseagreen",
    "mediumslateblue",
    "mediumspringgreen",
    "mediumturquoise",
    "mediumvioletred",
    "midnightblue",
    "mintcream",
    "mistyrose",
    "moccasin",
    "navajowhite",
    "navy",
    "oldlace",
    "olive",
    "olivedrab",
    "orange",
    "orangered",
    "orchid",
    "palegoldenrod",
    "palegreen",
    "paleturquoise",
    "palevioletred",
    "papayawhip",
    "peachpuff",
    "peru",
    "pink",
    "plum",
    "powderblue",
    "purple",
    "rebeccapurple",
    "red",
    "rosybrown",
    "royalblue",
    "saddlebrown",
    "salmon",
    "sandybrown",
    "seagreen",
    "seashell",
    "sienna",
    "silver",
    "skyblue",
    "slateblue",
    "slategray",
    "slategrey",
    "snow",
    "springgreen",
    "steelblue",
    "tan",
    "teal",
    "thistle",
    "tomato",
    "turquoise",
    "violet",
    "wheat",
    "white",
    "whitesmoke",
    "yellow",
    "yellowgreen",
    "transparent",
];

/// Checks if a string is a valid CSS named color.
fn is_valid_named_color(s: &str) -> bool {
    CSS3_NAMED_COLORS.contains(&s)
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
    }

    #[test]
    fn test_hsl_function() {
        assert!(CssColor::new("hsl(0, 100%, 50%)").is_ok());
        assert!(CssColor::new("hsl(360, 100%, 50%)").is_ok());
        assert!(CssColor::new("hsla(180, 50%, 50%, 0.5)").is_ok());
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
}
