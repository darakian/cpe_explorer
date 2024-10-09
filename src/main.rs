use std::fs;
use std::path::Path;
use roxmltree;
use rayon::prelude::*;
use clap::Parser;
use serde_json::json;
use regex::Regex;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to cpe dictionary xml
    #[arg(short, long)]
    dict: String,

    // Vendor name to filter by
    #[arg(short, long, help="Vendor name to filter on. Lowercase only.")]
    vendor: Option<String>,

    // Product name to filter by
    #[arg(short, long, help="Product name to filter on. Lowercase only.")]
    product: Option<String>,

    // Compress versions
    #[arg(short='c', long, action, help="Only show unqiue product:vendor combinations")]
    compress_versions: bool,

    // Check cpe23 passes nvd's regex
    #[arg(short='r', long, action, help="Validate cpe strings against NVD's validation regex")]
    validate_cpe23: bool,

    // Output as json
    #[arg(short, long, action, help="Export cpes in json. Ignores regex validation at the moment")]
    json_out: bool,
}

use cpe_explorer::cpedict::{parse_cpe_node, CpeEntry, CVE_CPE23_VALID_REGEX_STR};
use cpe_explorer::nvdarchive;

fn main() {
    let cpe23_valid_regex = Regex::new(CVE_CPE23_VALID_REGEX_STR).unwrap();
    
    let args = Args::parse();
    
    //Read in XML
    let input_xml_file = Path::new(&args.dict);
    let raw_xml = nvdarchive::decompress_or_return(input_xml_file)
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

    // for entry in get_deprecated_entries(&cpe_entries) {
    //     // resolve_deprecation_chain(entry, &cpe_entries)
    //     println!("CPE: {}\nCPE23: {}", entry.get_cpe_name(), entry.get_cpe23_name());
    //     match entry.deprecated_by() {
    //         None => {println!("\t No replacement cpe");}
    //         Some(n) => {
    //             println!("\t Replaced by {}", n);

    //         }
    //     }
    // }

    // match args.validate_cpe23 {
    //     Some(false) => {
    //         cpe_entries.iter()
    //             .filter(|element| cpe23_valid_regex.is_match(element.get_cpe23_name().as_str())==false)
    //             .for_each(|element| {
    //             println!("{}", element.get_cpe23_name());
    //         });
    //     },
    //     _ => {}
    // };


    let mut results: Vec<_> = match (args.vendor, args.product) {
        (Some(v), Some(p)) => {
            cpe_entries.par_iter()
                .filter(|element| element.has_vendor(&v))
                .filter(|element| element.has_product(&p))
                .collect()
            }
        (Some(v), None) => {
            cpe_entries.par_iter()
                .filter(|element| element.has_vendor(&v))
                .collect()
            }
        (None, Some(p)) => {
            cpe_entries.par_iter()
                .filter(|element| element.has_product(&p))
                .collect()
            }
        (_, _) => {
            cpe_entries.par_iter()
                .filter(|element| true)
                .collect()
        }
    };
    match args.compress_versions {
        true => {
            results.sort();
            results.dedup();
        },
        false => {},
    }

    match args.json_out {
        true => {output_json(results)},
        false => {
            for res in results.iter() {
                println!("Matching cpe: {}", res.get_cpe23_name());
                match args.validate_cpe23 {
                    true => {println!("\tPasses regex validation: {}", cpe23_valid_regex.is_match(res.get_cpe23_name().as_str()));}
                    false => {}
                }
            }
        },
    }
}

fn output_json(cpe_entries: Vec<&CpeEntry>) {
    println!("{}", json!(cpe_entries));
}

fn get_deprecated_entries(cpe_entries: &Vec<CpeEntry>) -> Vec<&CpeEntry> {
    cpe_entries.par_iter()
        .filter(|e| e.is_deprecated())
        .collect()
}

fn resolve_deprecation_chain(cpe_entry: &CpeEntry, all_entries: &Vec<CpeEntry>) {
    let og_names = cpe_entry.get_names();
    match cpe_entry.deprecated_by() {
        None => {return},
        Some(n) => {
            all_entries.par_iter().for_each(|entry| {
                if entry.has_name(n) && entry.is_deprecated() {
                    println!("OG names: {:?}", og_names);
                    println!("Deprecated_by: {:?}", entry.get_names());
                    println!("Is deprecated: {:?}", entry.is_deprecated()); //Always false as of 28th Sept 2024
                }
            })
        }
    }
}




