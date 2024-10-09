use crate::cpestructures::{CpeEntry, Cpe23Entry, Cpe23Name};

pub fn parse_cpe_node(cpe_node: roxmltree::Node) -> CpeEntry {
    let node_cpe_name = cpe_node.attribute("name").expect("cpe name not available");
    let node_deprication_status = match cpe_node.attribute("deprecated") {
        Some(_) => true,
        None => false,
    };

    let node_deprication_date = match cpe_node.attribute("deprecation_date") {
        Some(d) => Some(d.to_string()),
        None => None
    };

    // Get cpe23 node(s) to parse
    let cpe23_child: roxmltree::Node = cpe_node
        .children()
        .filter(|n| n.is_element())
        .filter(|n| n.tag_name().name() == "cpe23-item")
        .collect::<Vec<_>>()
        .pop().expect("no cpe23 child");


    let node_cpe_23 = parse_cpe23(cpe23_child);

    CpeEntry::new(
        node_cpe_name.to_string(),
        node_deprication_status,
        node_deprication_date,
        node_cpe_23
        )
    }

fn parse_cpe23(cpe23_node: roxmltree::Node) -> Cpe23Entry {
    let node_cpe23_name = cpe23_node.attribute("name").expect("cpe name not available");
    let mut node_cpe23_deprecated = false;
    let mut node_cpe23_deprecated_date = None;
    let mut node_cpe23_deprecated_type = None;
    let mut node_cpe23_deprecated_by = None;


    let cpe23_deprecation_child = cpe23_node
        .children()
        .filter(|n| n.is_element())
        .filter(|n| n.tag_name().name() == "deprecation")
        .collect::<Vec<_>>()
        .pop();

    match cpe23_deprecation_child {
        None => {},
        Some(c) => {
            node_cpe23_deprecated = true;
            node_cpe23_deprecated_date = match c.attribute("date") {
                None => None,
                Some(d) => Some(d.to_string()),
            };
            let deprecated_by = c
                .children()
                .filter(|n| n.is_element())
                .collect::<Vec<_>>()
                .pop()
                .expect("could not unwrap deprecation by node");

            node_cpe23_deprecated_by = match deprecated_by.attribute("name") {
                None => None,
                Some(n) => Some(n.to_string()),
            };

            node_cpe23_deprecated_type = match deprecated_by.attribute("type") {
                None => None,
                Some(n) => Some(n.to_string()),
            };
        }
    }
    
    return Cpe23Entry::new(
        Cpe23Name::new(node_cpe23_name),
        node_cpe23_deprecated,
        node_cpe23_deprecated_type,
        node_cpe23_deprecated_date,
        node_cpe23_deprecated_by
        )
}