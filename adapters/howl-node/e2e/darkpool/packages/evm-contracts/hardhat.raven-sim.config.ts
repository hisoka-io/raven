// Howl's own config plus a local anvil network for the Raven simulation, so their file stays as pinned.
import type { HardhatUserConfig } from "hardhat/config";
import base from "./hardhat.config";

const config: HardhatUserConfig = {
  ...base,
  networks: {
    ...base.networks,
    simAnvil: {
      url: process.env.SIM_RPC_URL || "http://127.0.0.1:18955",
      allowUnlimitedContractSize: true,
      timeout: 600000,
    },
  },
};

export default config;
