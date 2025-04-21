# Objectives

1. Make the creations CCIP complaint
2. Deploy Mock CCIP contracts
3. Test it on chain (Sepolia to Amoy)

## Notes

https://cll-devrel.gitbook.io/ccip-bootcamp/day-1/how-to-use-chainlink-ccip

Any contract that implements `CCIPReceiver.sol` can be a CCIP receiver
To send CCIP Messages the smart contract on the source blockchain must call the ccipSend() function, which is defined in the `IRouterClient.sol` interface.
The CCIP Message which is being sent is a type of `EVM2AnyMessage` Solidity struct from the `Client` library.

To receive CCIP Messages, the smart contract on the destination blockchain must implement the `IAny2EVMMessageReceiver` interface
