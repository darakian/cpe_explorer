pub mod cpedict;
pub mod cpestructures;

// See: https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
pub static NVD_CPE23_VALID_REGEX_STR: &str = r###"cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"###;
// See: https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_cna_affected_items_cpes
pub static CVE_CPE23_VALID_REGEX_STR: &str = r###"([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9._\-~%]*){0,6})|(cpe:2\.3:[aho*\-](:(((\?*|\*?)([a-zA-Z0-9\-._]|(\\[\\*?!"#$%&'()+,/:;<=>@\[\]\^`{|}~]))+(\?*|\*?))|[*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-._]|(\\[\\*?!"#$%&'()+,/:;<=>@\[\]\^`{|}~]))+(\?*|\*?))|[*\-])){4})"###;
