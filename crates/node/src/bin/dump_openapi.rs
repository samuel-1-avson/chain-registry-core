// Emit the node's OpenAPI spec to stdout without running a full node.
//
//   cargo run -p chain-registry-node --bin dump-openapi > openapi.json
//
// The explorer's `npm run gen-types` reads either this file or a live
// `/v1/openapi.json`, whichever is more convenient.

use node::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let spec = ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&spec).expect("serialize OpenAPI spec");
    println!("{}", json);
}
