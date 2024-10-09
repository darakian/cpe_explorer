use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Deserialize, Serialize)]
pub struct CpeEntry {
    cpe_name: String,
    deprecated: bool,
    deprecated_date: Option<String>,
    cpe23: Cpe23Entry,
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

    pub fn has_name(&self, name: &String) -> bool {
        name == self.get_names().0 || name == self.get_names().0
    }

    pub fn has_vendor(&self, vendor_name: &String) -> bool {
        self.cpe23.cpe23_name.vendor == *vendor_name
    }

    pub fn get_vendor(&self) -> &String {
        &self.cpe23.cpe23_name.vendor
    }

    pub fn has_product(&self, product_name: &String) -> bool {
        self.cpe23.cpe23_name.product == *product_name
    }

    pub fn get_product(&self) -> &String {
        &self.cpe23.cpe23_name.product
    }

    pub fn get_vendor_product(&self) -> (&String, &String) {
        self.cpe23.cpe23_name.get_vendor_product_tuple()
    }
}

impl PartialEq for CpeEntry {
    fn eq(&self, other: &CpeEntry) -> bool {
        self.get_vendor_product() == other.get_vendor_product()
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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cpe23Name {
    cpe_version: String,
    part: String,
    vendor: String,
    product: String,
    version: String,
    update: String,
    edition: String,
    language: String,
    sw_edition: String,
    target_sw: String,
    target_hw: String,
    other: String,
}

impl Cpe23Name {
    pub fn new (cpe_string: &str) -> Self {
        let cpe_parts = cpe_string.split(':').collect::<Vec<_>>();
        Cpe23Name {
            cpe_version: cpe_parts[1].to_string(),
            part: cpe_parts[2].to_string(),
            vendor: cpe_parts[3].to_string(),
            product: cpe_parts[4].to_string(),
            version: cpe_parts[5].to_string(),
            update: cpe_parts[6].to_string(),
            edition: cpe_parts[7].to_string(),
            language: cpe_parts[8].to_string(),
            sw_edition: cpe_parts[9].to_string(),
            target_sw: cpe_parts[10].to_string(),
            target_hw: cpe_parts[11].to_string(),
            other: cpe_parts[12].to_string(),
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

    fn get_version_tuple(&self) -> (&String, &String, &String, &String, &String, &String, &String, &String) {
        (&self.version, &self.update, &self.edition, &self.language, &self.sw_edition, &self.target_sw, &self.target_hw, &self.other)
    }
}

impl PartialEq for Cpe23Name {
    fn eq(&self, other: &Cpe23Name) -> bool {
        self.get_vendor_product_tuple() == other.get_vendor_product_tuple()
    }
}

impl Eq for Cpe23Name{}
