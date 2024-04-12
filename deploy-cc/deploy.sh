curl -skSL https://raw.githubusercontent.com/arc9693/cc-azurefile-csi-driver/master/deploy-cc/install-driver.sh | bash -s master --
kubectl create -f https://raw.githubusercontent.com/arc9693/cc-azurefile-csi-driver/master/deploy-cc/example/storageclass-cc-azurefile-csi.yaml
kubectl create -f https://raw.githubusercontent.com/arc9693/cc-azurefile-csi-driver/master/deploy-cc/example/storageclass-cc-azurefile-csi-premium.yaml
