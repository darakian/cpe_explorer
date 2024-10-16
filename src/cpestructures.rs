use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Deserialize, Serialize)]
pub struct CpeEntry {
    cpe_name: String,
    deprecated: bool,
    deprecated_date: Option<String>,
    pub cpe23: Cpe23Entry,
}

impl CpeEntry{
    pub fn new(cpe_name: String, deprecated: bool, deprecated_date: Option<String>, cpe23: Cpe23Entry) -> Self {
        CpeEntry{
            cpe_name: cpe_name,
            deprecated: deprecated,
            deprecated_date: deprecated_date,
            cpe23: cpe23
        }
    }

    pub fn get_names(&self) -> (&String, String) {
        (&self.cpe_name, self.cpe23.cpe23_name.get_name())
    }

    pub fn get_cpe_name(&self) -> &String {
        &self.cpe_name
    }

    pub fn get_cpe23_name(&self) -> String {
        self.cpe23.cpe23_name.get_name()
    }

    pub fn deprecated_by(&self) -> &Option<String> {
        &self.cpe23.cpe23_deprecated_by
    }

    pub fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    pub fn get_cpe23_parts(&self) -> &Cpe23Name {
        self.cpe23.get_cp23_parts()
    }
}

impl PartialEq for CpeEntry {
    fn eq(&self, other: &CpeEntry) -> bool {
        (self.get_cpe23_parts().vendor == other.get_cpe23_parts().vendor) &&
        self.get_cpe23_parts().product == other.get_cpe23_parts().product
    }
}

impl Eq for CpeEntry {}

impl Ord for CpeEntry {
    fn cmp(&self, other: &CpeEntry) -> Ordering {
        self.cpe23.cpe23_name.get_name().cmp(
            &other.cpe23.cpe23_name.get_name()
            )
    }
}

impl PartialOrd for CpeEntry {
    fn partial_cmp(&self, other: &CpeEntry) -> Option<Ordering> {
        Some(self.cpe23.cpe23_name.get_name().cmp(
            &other.cpe23.cpe23_name.get_name()
            ))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cpe23Entry {
    cpe23_name: Cpe23Name,
    cpe23_deprecated: bool,
    cpe23_deprecated_type: Option<String>,
    cpe23_deprecated_date: Option<String>,
    cpe23_deprecated_by: Option<String>,
}

impl Cpe23Entry{
    pub fn new(cpe23_name: Cpe23Name, cpe23_deprecated: bool, cpe23_deprecated_type: Option<String>, cpe23_deprecated_date: Option<String>, cpe23_deprecated_by: Option<String>) -> Self {
        Cpe23Entry{
            cpe23_name: cpe23_name,
            cpe23_deprecated: cpe23_deprecated,
            cpe23_deprecated_type: cpe23_deprecated_type,
            cpe23_deprecated_date: cpe23_deprecated_date,
            cpe23_deprecated_by: cpe23_deprecated_by
        }
    }

    fn get_cp23_parts(&self) -> &Cpe23Name {
        &self.cpe23_name
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cpe23Name {
    pub cpe_version: String,
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe23Name {
    pub fn new (cpe_string: &str) -> Self {
        let cpe_string = cpe_string.replace("\\:","🦞");
        let cpe_parts = cpe_string.split(':').collect::<Vec<_>>();
        Cpe23Name {
            cpe_version: cpe_parts[1].replace("🦞", ":"),
            part: cpe_parts[2].replace("🦞", ":"),
            vendor: cpe_parts[3].replace("🦞", ":"),
            product: cpe_parts[4].replace("🦞", ":"),
            version: cpe_parts[5].replace("🦞", ":"),
            update: cpe_parts[6].replace("🦞", ":"),
            edition: cpe_parts[7].replace("🦞", ":"),
            language: cpe_parts[8].replace("🦞", ":"),
            sw_edition: cpe_parts[9].replace("🦞", ":"),
            target_sw: cpe_parts[10].replace("🦞", ":"),
            target_hw: cpe_parts[11].replace("🦞", ":"),
            other: cpe_parts[12].replace("🦞", ":"),
        }
    }

    fn get_name(&self) -> String {
        "cpe:".to_owned()+
        &self.cpe_version+":"+
        &self.part+":"+
        &self.vendor+":"+
        &self.product+":"+
        &self.version+":"+
        &self.update+":"+
        &self.edition+":"+
        &self.language+":"+
        &self.sw_edition+":"+
        &self.target_sw+":"+
        &self.target_hw+":"+
        &self.other
    }

    fn get_vendor_product_tuple(&self) -> (&String, &String) {
        (&self.vendor, &self.product)
    }

}

impl PartialEq for Cpe23Name {
    fn eq(&self, other: &Cpe23Name) -> bool {
        self.get_vendor_product_tuple() == other.get_vendor_product_tuple()
    }
}

impl Eq for Cpe23Name{}
