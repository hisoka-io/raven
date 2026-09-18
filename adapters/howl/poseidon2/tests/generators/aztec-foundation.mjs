import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_VERSION = "2.1.11";
const ENV_NAME = "AZTEC_FOUNDATION_ROOT";

export const loadAztecFoundation = async () => {
  const packageRoot = process.env[ENV_NAME]?.trim();
  if (!packageRoot) {
    throw new Error(`${ENV_NAME} must point to the @aztec/foundation package root`);
  }

  const packageJsonPath = resolve(packageRoot, "package.json");
  const cryptoPath = resolve(packageRoot, "dest/crypto/index.js");
  const fieldsPath = resolve(packageRoot, "dest/fields/index.js");

  let packageMetadata;
  try {
    packageMetadata = JSON.parse(await readFile(packageJsonPath, "utf8"));
  } catch (error) {
    throw new Error(`${ENV_NAME} does not contain a readable @aztec/foundation package`, {
      cause: error,
    });
  }
  if (packageMetadata.version !== EXPECTED_VERSION) {
    throw new Error(
      `${ENV_NAME} contains @aztec/foundation ${packageMetadata.version ?? "with no version"}; expected ${EXPECTED_VERSION}`,
    );
  }

  let crypto;
  let fields;
  try {
    [crypto, fields] = await Promise.all([
      import(pathToFileURL(cryptoPath).href),
      import(pathToFileURL(fieldsPath).href),
    ]);
  } catch (error) {
    throw new Error(`${ENV_NAME} does not contain the required Aztec oracle modules`, {
      cause: error,
    });
  }
  if (
    typeof crypto.poseidon2Hash !== "function" ||
    typeof crypto.poseidon2Permutation !== "function" ||
    typeof fields.Fr !== "function"
  ) {
    throw new Error(`${ENV_NAME} exposes an incompatible Aztec oracle API`);
  }

  return {
    Fr: fields.Fr,
    poseidon2Hash: crypto.poseidon2Hash,
    poseidon2Permutation: crypto.poseidon2Permutation,
  };
};
