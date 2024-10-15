use std::path::Path;
use roxmltree;
use rayon::prelude::*;
use clap::{Parser, ValueEnum};
use serde_json::json;
use regex::Regex;

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CpeRegexs {
    NVD,
    CVE,
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to cpe dictionary xml
    #[arg(short='d', long)]
    dict: String,

    // Vendor name to filter by
    #[arg(short='v', long, help="Vendor name to filter on")]
    vendor: Option<String>,

    // Product name to filter by
    #[arg(short='p', long, help="Product name to filter on")]
    product: Option<String>,

    // Filter by regex validation
    #[arg(short='r', long, action, help="Validate cpe strings against NVD's validation regex")]
    validate_cpe23: Option<bool>,

    // Filter by deprecation status
    #[arg(short='n', long, action, help="Filter on deprecation status")]
    deprecation_status: Option<bool>,

    // Pick between the NVD regular expression or the CVE org one.
    #[arg(short='x', long, value_enum, default_value = "nvd", help="Choice of cpe validation regex.")]
    regex_choice: CpeRegexs,

    // Compress versions
    #[arg(short='c', long, action, help="Only show unqiue product:vendor combinations")]
    compress_versions: bool,

    // Output as json
    #[arg(short='j', long, action, help="Export cpes in json. Ignores regex validation at the moment")]
    json_out: bool,
}

use cpe_explorer::cpedict::{parse_cpe_node, get_xml_as_string_from_path};
use cpe_explorer::{NVD_CPE23_VALID_REGEX_STR, CVE_CPE23_VALID_REGEX_STR};

fn main() {
    let args = Args::parse();

    let cpe23_valid_regex = match args.regex_choice {
        CpeRegexs::NVD => {Regex::new(NVD_CPE23_VALID_REGEX_STR).unwrap()},
        CpeRegexs::CVE => {Regex::new(CVE_CPE23_VALID_REGEX_STR).unwrap()},
    };
    
    
    //Read in XML
    let input_xml_file = Path::new(&args.dict);
    let raw_xml = get_xml_as_string_from_path(input_xml_file)
        .expect("could not read input file");
    // let raw_xml = fs::read_to_string(input_xml_file)
    //             .expect("could not read input file");
    let cpe_xml_doc = roxmltree::Document::parse(&raw_xml).expect("could not parse input xml");
    
    let cpe_list = cpe_xml_doc.root_element();
    let xml_cpe_items: Vec<_> = cpe_list
        .children()
        .filter(|n| n.is_element())
        .filter(|n| n.tag_name().name() != "generator")
        .collect();

    let cpe_entries: Vec<_> = xml_cpe_items
        .into_par_iter()
        .map(|entry| parse_cpe_node(entry))
        .collect();

    let mut results: Vec<_> = cpe_entries.par_iter()
        .filter( |element| match &args.vendor { 
            Some(v) => {element.has_vendor(&v.to_lowercase())},
            None => {true},
        })
        .filter( |element| match &args.product { 
            Some(p) => {element.has_product(&p.to_lowercase())},
            None => {true},
        })
        .filter( |element| match &args.validate_cpe23 { 
            Some(true) => {cpe23_valid_regex.is_match(element.get_cpe23_name().as_str())==true},
            Some(false) => {cpe23_valid_regex.is_match(element.get_cpe23_name().as_str())==false},
            _ => {true} //eg. Ignore filter
        })
        .filter( |element| match &args.deprecation_status { 
            Some(true) => {element.is_deprecated()},
            Some(false) => {!element.is_deprecated()},
            _ => {true} //eg. Ignore filter
        })
        .collect();


    match args.compress_versions {
        true => {
            results.sort();
            results.dedup();
        },
        false => {},
    }

    match args.json_out {
        true => {println!("{}", json!((results)))},
        false => {
            for res in results.iter() {
                println!("Matching cpe: {}", res.get_cpe23_name());
                match args.validate_cpe23 {
                    Some(true) => {println!("\tPasses regex validation: {}", cpe23_valid_regex.is_match(res.get_cpe23_name().as_str()));},
                    Some(false) => {},
                    _ => {}
                }
            }
        },
    }
}

// fn resolve_deprecation_chain(cpe_entry: &CpeEntry, all_entries: &Vec<CpeEntry>) {
//     let og_names = cpe_entry.get_names();
//     match cpe_entry.deprecated_by() {
//         None => {return},
//         Some(n) => {
//             all_entries.par_iter().for_each(|entry| {
//                 if entry.has_name(n) && entry.is_deprecated() {
//                     println!("OG names: {:?}", og_names);
//                     println!("Deprecated_by: {:?}", entry.get_names());
//                     println!("Is deprecated: {:?}", entry.is_deprecated()); //Always false as of 28th Sept 2024
//                 }
//             })
//         }
//     }
// }




