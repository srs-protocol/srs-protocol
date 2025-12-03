// main包，用于启动合约
package main

import (
	sdk "chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
	"orasrs-chainmaker-contract/orasrscontract"
)

func main() {
	contract := &orasrscontract.OrasrsStakingContract{}
	sdk.RegisterContract(contract)
	sdk.Run()
}