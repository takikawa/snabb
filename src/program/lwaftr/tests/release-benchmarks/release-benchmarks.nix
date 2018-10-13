with import <nixpkgs> {};

let dataset = stdenv.mkDerivation {
  name = "lwaftr-dataset";

  dataset = (fetchTarball {
    url = https://people.igalia.com/atakikawa/lwaftr_benchmarking_dataset.tar.gz;
    # not supported in old NixOS
    #sha256 = "48b4204e656d19aa9f2b4023104f2483e66df7523e28188181fb3d052445eaba";
  });

  snabb_pci0 = builtins.getEnv "SNABB_PCI0";
  snabb_pci1 = builtins.getEnv "SNABB_PCI1";
  snabb_pci2 = builtins.getEnv "SNABB_PCI2";
  snabb_pci3 = builtins.getEnv "SNABB_PCI3";
  snabb_pci4 = builtins.getEnv "SNABB_PCI4";
  snabb_pci5 = builtins.getEnv "SNABB_PCI5";
  snabb_pci6 = builtins.getEnv "SNABB_PCI6";
  snabb_pci7 = builtins.getEnv "SNABB_PCI7";

  # copy confs from script directory to nix store for builder
  confs = stdenv.lib.source.sourceFilesBySuffices . [".conf"];

  # include snabb executable (for generating configs)
  snabb = ../../../../snabb;

  # config generation parameteres
  ipv4     = "193.5.1.100";
  num_ips  = "1000062";
  b4       = "fc00:1:2:3:4:5:0:7e";
  br_addr  = "fc00:100";
  psid_len = "6";

  # build config files for test cases, include pcaps from tarball
  builder = builtins.toFile "builder.sh" "
    source $stdenv/setup
    mkdir $out
    for conf in $confs/lwaftr*.conf
    do
        target=$out/`basename $conf`
        sudo $snabb lwaftr generate-configuration --include $conf $ipv4 $num_ips $br_addr $b4 $psid_len > $target
        sed -i -e \"s/<SNABB_PCI0>/$snabb_pci0/; \\
                    s/<SNABB_PCI1>/$snabb_pci1/; \\
                    s/<SNABB_PCI2>/$snabb_pci2/; \\
                    s/<SNABB_PCI3>/$snabb_pci3/; \\
                    s/<SNABB_PCI4>/$snabb_pci4/; \\
                    s/<SNABB_PCI5>/$snabb_pci5/; \\
                    s/<SNABB_PCI6>/$snabb_pci6/; \\
                    s/<SNABB_PCI7>/$snabb_pci7/\" \\
            $target
    done
    cp $dataset/*.pcap $out/
    ";
};
in runCommand "dummy" { dataset = dataset; snabb = snabb } ""