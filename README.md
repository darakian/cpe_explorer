# cpe_explorer

An opinionated command line tool used to explore the nvd CPE dictionary.
The dictionary itself is [available here](https://nvd.nist.gov/products/cpe) and seems to update daily.

```
An exploration tool for the NVD cpe dict

Usage: cpe_explorer [OPTIONS] --dict <DICT>

Options:
  -d, --dict <DICT>
          Path to cpe dictionary xml
  -v, --vendor <VENDOR>
          Vendor name to filter on. Can be negated with a leading !
  -p, --product <PRODUCT>
          Product name to filter on. Can be negated with a leading !
  -V, --version <VERSION>
          Version to filter on. Can be negated with a leading !
  -u, --update <UPDATE>
          Update to filter on. Can be negated with a leading !
  -e, --edition <EDITION>
          Edition to filter on. Can be negated with a leading !
  -l, --language <LANGUAGE>
          Language to filter on. Can be negated with a leading !
  -s, --sw-edition <SW_EDITION>
          Software edition to filter on. Can be negated with a leading !
  -S, --target-sw <TARGET_SW>
          Target software (eg. environment) to filter on. Can be negated with a leading !
  -H, --target-hw <TARGET_HW>
          Target hardware (eg. environment) to filter on. Can be negated with a leading !
  -o, --other <OTHER>
          'Other' to filter on. Can be negated with a leading !
  -r, --validate-cpe23 <VALIDATE_CPE23>
          Validate cpe strings against NVD's validation regex [possible values: true, false]
  -n, --deprecation-status <DEPRECATION_STATUS>
          Filter on deprecation status [possible values: true, false]
  -x, --regex-choice <REGEX_CHOICE>
          Choice of cpe validation regex. [default: nvd] [possible values: nvd, cve]
  -c, --compress-versions
          Only show unqiue product:vendor combinations
  -j, --json-out
          Export cpes in json
  -h, --help
          Print help
```

Under active development, but usable for filtering along the various cpe23 parts and by cpe23 status.

## Examples
filtering by vendor
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -v nist
Matching cpe: "cpe:2.3:a:nist:hipaa_security_rule_toolkit:1.0.0.0:*:*:*:*:*:*:*"
```
or by product
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -p cve-services
Matching cpe: "cpe:2.3:a:cve:cve-services:-:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.1:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.1.1:*:*:*:*:*:*:*"
```
or a vendor but not a specific product
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-09102024.xml -v mitre -p !caldera
Matching cpe: cpe:2.3:a:mitre:cve_services:1.1.1:*:*:*:*:node.js:*:*
Matching cpe: cpe:2.3:a:mitre:risk_radar:1.0.0:*:*:*:*:*:*:*
```
All filters can be mixed.

The `-c` flag "compresses" versions which can simplify exploration of product/vendor combinations. For the purposes of this flag everthing after the product field is treated as one long version string (becasue it kind of is). At the moment no consideration is given as to which version string to display to the user in compression mode.
