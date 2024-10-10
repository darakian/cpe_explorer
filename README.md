# cpe_explorer

An opinionated command line tool used to explore the nvd CPE dictionary.
The dictionary itself is [available here](https://nvd.nist.gov/products/cpe) and seems to update daily.

```
❯❯❯ cpe_explorer --help
An exploration tool for the NVD cpe dict

Usage: cpe_explorer [OPTIONS] --dict <DICT>

Options:
  -d, --dict <DICT>        Path to cpe dictionary xml
  -v, --vendor <VENDOR>    Vendor name to filter on. Lowercase only.
  -p, --product <PRODUCT>  Product name to filter on. Lowercase only.
  -c, --compress-versions  Only show unqiue product:vendor combinations
  -r, --validate-cpe23     Validate cpe strings against NVD's validation regex
  -j, --json-out           Export cpes in json. Ignores regex validation at the moment
  -h, --help               Print help
  -V, --version            Print version
  ```

Under active development, but it's currently most useful in getting cpe23 strings that match a given vendor and/or product.
eg.
filtering by vendor only
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -v nist
Matching cpe: "cpe:2.3:a:nist:hipaa_security_rule_toolkit:1.0.0.0:*:*:*:*:*:*:*"
```
or by product only
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -p cve-services
Matching cpe: "cpe:2.3:a:cve:cve-services:-:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.0.1:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:cve:cve-services:1.1.1:*:*:*:*:*:*:*"
```
or both
```
❯❯❯ cpe_explorer -d official-cpe-dictionary_v2.3-03102024.xml -v palm -p blazer
Matching cpe: "cpe:2.3:a:palm:blazer:3.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.0:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.2:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.3:*:*:*:*:*:*:*"
Matching cpe: "cpe:2.3:a:palm:blazer:4.5:*:*:*:*:*:*:*"
```
The `-c` flag "compresses" versions which can simplify exploration of product/vendor combinations. For the purposes of this flag everthing after the product field is treated as one long version string (becasue it kind of is). At the moment no consideration is given as to which version string to display to the user in compression mode.
