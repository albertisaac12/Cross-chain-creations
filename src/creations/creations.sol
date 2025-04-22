// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title dappunk NFT Minting Contract.
/// @notice 1-of-1 NFTs created in the dappunk app by creators.
/// @author dappunk - https://dappunk.com

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";

// Chainlink CCIP imports
import {IRouterClient} from "@chainlink/contracts/src/v0.8/ccip/interfaces/IRouterClient.sol";
import {Client} from "@chainlink/contracts/src/v0.8/ccip/libraries/Client.sol";
import {CCIPReceiver} from "@chainlink/contracts/src/v0.8/ccip/applications/CCIPReceiver.sol";

abstract contract stateVar {
    uint256 public platformFee;
    uint256 public pioneerFee;
    bool public uriSuffixEnabled = false;
    bool public isDeprecated = false;
    string public uriSuffix;
    string public baseUri;
    string public stealthUri;
    string public name;
    string public symbol;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant FUND_MANAGER_ROLE = keccak256("FUND_MANAGER_ROLE");
    bytes32 public constant AGENCY_MANAGER_ROLE = keccak256("AGENCY_MANAGER_ROLE");
    bytes32 public constant CONTRACT_APPROVER_ROLE = keccak256("CONTRACT_APPROVER_ROLE");
    bytes32 public constant MINT_VALIDATOR_ROLE = keccak256("MINT_VALIDATOR_ROLE");
    bytes32 public constant REFUND_MANAGER_ROLE = keccak256("REFUND_MANAGER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant MARKET_PLACE = keccak256("MARKET_PLACE");

    struct NFTVoucher {
        uint256 tokenId;
        uint256 price;
        uint256 quantity;
        uint256 buyerQty;
        uint256 start;
        uint256 end;
        // uint256 chainSelector;
        // uint256 nonce;
        uint96 royalty;
        bool isStealth;
        bool isSbt;
        bytes creator;
        bytes validator;
    }

    struct crossChainReceive {
        uint256 tokenId;
        uint256 quantity;
        uint256 tokenMaxQty;
        uint96 royalty;
        bool isStealth;
        bool isSbt;
        address creator;
    }

    mapping(uint256 => bool) public sbt;
    mapping(uint256 => bool) public stealth;
    mapping(address => bool) public approvedContracts;
    mapping(address => bool) public pioneers;
    mapping(address => bool) public supportedTokens; // Supported ERC20 Tokens for payment
    mapping(address => uint256) public agencyFee; // Agency fee
    mapping(uint256 => uint256) public tokenMaxQty; // Total quantity of a token
    mapping(uint256 => uint256) public tokenMintedQty; // Amount of token minted
    mapping(address => address) public agencyCreator; // creator => agency
    mapping(uint256 => address) public creatorRegistry; // Creator of token
    mapping(address => uint256) public nonces;
    mapping(address => bool) public allowedRouters; // all routers allowed to

    event Minted(address indexed creator, uint256 indexed tokenId, uint256 quantity, address indexed buyer);
    event Burnt(uint256 indexed tokenId, uint256 quantity);
    event Refunded(uint256 indexed tokenId, address indexed from, uint256 qty);
    event Locked(uint256 tokenId);
    event Unlocked(uint256 tokenId);

    error AccessDenied(bytes32 role, address sender);
    error AlreadyAdded(address account);
    error Deprecated();
    error InsufficientBalance();
    error InvalidPrice(uint256 tokenId, uint256 price);
    error InvalidSender(address sender);
    error NonTransferableToken();
    error NotSupported(address account);
    error NotTokenCreator(address creator, uint256 tokenId);
    error NotTokenOwner(address wallet, uint256 tokenId, uint256 qty);
    error TransferError();
    error TokenSaleNotStarted(uint256 tokenId, uint256 start, uint256 now);
    error TokenSaleEnded(uint256 tokenId, uint256 end, uint256 now);
    error InvalidTokenQty721(uint256 tokenId);
    error InvalidTokenQty(uint256 tokenId, uint256 expected, uint256 actual);
}

contract dappunkCreations is
    stateVar,
    ERC1155,
    ERC2981,
    ERC2771Context,
    CCIPReceiver,
    AccessControl,
    EIP712,
    ReentrancyGuard
{
    using Address for address;
    using Strings for uint256;

    constructor(
        address manager,
        address minter,
        address fundManager,
        address agencyManager,
        address contractApprover,
        address mintValidator,
        address refundManager,
        address[] memory relayers,
        address forwarder,
        address router
    ) ERC1155("") EIP712("moshpit", "1") ERC2771Context(forwarder) CCIPReceiver(router) {
        baseUri = "NoUrl";
        stealthUri = "StealthUrl";
        platformFee = 1000; // 1000 means 10%
        pioneerFee = 500;
        name = "dpNftV1";
        symbol = "DPN1";
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(MINTER_ROLE, minter);
        _grantRole(FUND_MANAGER_ROLE, fundManager);
        _grantRole(AGENCY_MANAGER_ROLE, agencyManager);
        _grantRole(CONTRACT_APPROVER_ROLE, contractApprover);
        _grantRole(MINT_VALIDATOR_ROLE, mintValidator);
        _grantRole(REFUND_MANAGER_ROLE, refundManager);
        _grantRole(MINTER_ROLE, forwarder);
        for (uint256 i = 0; i < relayers.length; i++) {
            _grantRole(RELAYER_ROLE, relayers[i]);
        }
        _setDefaultRoyalty(msg.sender, 1000);
    }

    modifier deprecated() {
        if (isDeprecated) revert Deprecated();
        _;
    }

    /// @notice Mint the nft native currency.
    /// @param voucher NFTVoucher that describes the NFT to be redeemed.
    function mintNftNative(NFTVoucher calldata voucher, address buyer) external payable deprecated nonReentrant {
        address creator = verifyVoucher(voucher);
        uint256 price = voucher.price * voucher.buyerQty;
        if (msg.value < price) revert InsufficientBalance();

        uint256 fee = fees(price, pioneers[creator]);

        mint(
            creator,
            buyer,
            voucher.tokenId,
            voucher.royalty,
            voucher.isSbt,
            voucher.isStealth,
            voucher.quantity,
            voucher.buyerQty
        );

        Address.sendValue(payable(creator), price - fee);

        address agencyWallet = agencyCreator[creator];
        if (agencyWallet != address(0)) {
            uint256 agencyAmount = agencyFees(price, agencyWallet);
            Address.sendValue(payable(agencyWallet), agencyAmount);
        }
    }

    /// @notice Mint the nft with token.
    /// @param voucher NFTVoucher that describes the NFT to be redeemed.
    /// @param tokenAddress The Address of token used to pay for the NFT.
    function mintNftWithToken(NFTVoucher calldata voucher, address tokenAddress, address buyer)
        external
        deprecated
        nonReentrant
    {
        if (!supportedTokens[tokenAddress]) revert NotSupported(tokenAddress);
        address creator = verifyVoucher(voucher);
        uint256 price = voucher.price * voucher.buyerQty;
        IERC20 token = IERC20(tokenAddress);

        uint256 fee = fees(price, pioneers[creator]);

        // Receive the funds
        token.transferFrom(buyer, address(this), price);
        mint(
            creator,
            buyer,
            voucher.tokenId,
            voucher.royalty,
            voucher.isSbt,
            voucher.isStealth,
            voucher.quantity,
            voucher.buyerQty
        );

        token.transfer(creator, price - fee);

        address agencyWallet = agencyCreator[creator];
        if (agencyWallet != address(0)) {
            uint256 agencyAmount = agencyFees(price, agencyWallet);
            token.transfer(agencyWallet, agencyAmount);
        }
    }

    /// @notice Mint the NFT from the dappunk api.
    /// @param voucher NFTVoucher that describes the NFT to be redeemed.
    /// @param buyer The user who is buying the NFT.
    function mintNft(NFTVoucher calldata voucher, address buyer) external deprecated onlyRole(MINTER_ROLE) {
        // onlyRole
        address creator = verifyVoucher(voucher);
        mint(
            creator,
            buyer,
            voucher.tokenId,
            voucher.royalty,
            voucher.isSbt,
            voucher.isStealth,
            voucher.quantity,
            voucher.buyerQty
        );
    }

    /// @notice Mint the NFT using relayers
    /// @param voucher NFTVoucher that describes the NFT to be redeemed.
    /// @param buyer The user who is buying the NFT
    function mintNftGasless(NFTVoucher calldata voucher, address buyer)
        external
        payable
        deprecated
        onlyRole(RELAYER_ROLE)
    {
        address creator = verifyVoucher(voucher);
        uint256 price = voucher.price * voucher.buyerQty;
        if (msg.value < price) revert InsufficientBalance();

        uint256 fee = fees(price, pioneers[creator]);

        mint(
            creator,
            buyer,
            voucher.tokenId,
            voucher.royalty,
            voucher.isSbt,
            voucher.isStealth,
            voucher.quantity,
            voucher.buyerQty
        );

        Address.sendValue(payable(creator), price - fee);

        address agencyWallet = agencyCreator[creator];
        if (agencyWallet != address(0)) {
            // uint256 agencyAmount = (price * agencyFee[agencyWallet])/_feeDenominator();
            uint256 agencyAmount = agencyFees(price, agencyWallet);
            Address.sendValue(payable(agencyWallet), agencyAmount);
        }
    }

    /// @notice Internal minting function that mints the NFT.
    /// @param creator Wallet of the NFT creater.
    /// @param buyer Wallet of the buyer.
    /// @param tokenId Token that is being minted.
    /// @param tokenRoyalty The price of the nft.
    /// @param quantity Total qty of the mint.
    /// @param buyerQty Qty to be minted by this buyer.
    /// @param isSBT Sets the token as non-transferable.
    /// @param isStealth Sets the token as stealth.
    function mint(
        address creator,
        address buyer,
        uint256 tokenId,
        uint96 tokenRoyalty,
        bool isSBT,
        bool isStealth,
        uint256 quantity,
        uint256 buyerQty
    ) private {
        // require(tokenMintedQty[tokenId] + buyerQty <= tokenMaxQty[tokenId], "INSUFFICIENT: All token are minted");
        _mint(buyer, tokenId, buyerQty, "");
        // For the first mint
        if (tokenMaxQty[tokenId] == 0) {
            tokenMintedQty[tokenId] = 0;
            tokenMaxQty[tokenId] = quantity;
            _setTokenRoyalty(tokenId, creator, tokenRoyalty);
            creatorRegistry[tokenId] = creator;
            if (isSBT) {
                sbt[tokenId] = true;
                emit Locked(tokenId);
            }
            if (isStealth) {
                stealth[tokenId] = true;
            }
        }
        tokenMintedQty[tokenId] += buyerQty;
        emit Minted(creator, tokenId, buyerQty, buyer);
    }

    /// @notice Calculats the fees.
    /// @param value The price of the NFT.
    /// @param isPioneer Is the creator a pioneer.
    /// @return Calculated platform fees.
    function fees(uint256 value, bool isPioneer) internal view returns (uint256) {
        if (isPioneer) {
            return ((value * pioneerFee) / _feeDenominator());
        } else {
            return ((value * platformFee) / _feeDenominator());
        }
    }

    /// @notice Calculats the agency fees.
    /// @param value The price of the NFT.
    /// @param agency Agency wallet address.
    /// @return Calculated agency fees.
    function agencyFees(uint256 value, address agency) internal view returns (uint256) {
        return ((value * agencyFee[agency]) / _feeDenominator());
    }

    /// @notice Verifies the signature for a given NFTVoucher, returning the address of the creator.
    /// @param voucher NFTVoucher describing an NFT.
    /// @return creator Address of the creator of the NFT.
    function verifyVoucher(NFTVoucher calldata voucher) public view returns (address) {
        // Perform general validations
        _validateVoucher(voucher);

        // Verify signatures
        address creator = _verifySignatures(voucher);

        // Timestamp verification
        uint256 _now = block.timestamp;
        if (voucher.start != 0 && _now < voucher.start) {
            revert TokenSaleNotStarted(voucher.tokenId, voucher.start, _now);
        } //0
        if (voucher.end != 0 && _now > voucher.end) {
            revert TokenSaleEnded(voucher.tokenId, voucher.end, _now);
        } // 0

        return creator;
    }

    function _validateVoucher(NFTVoucher calldata voucher) internal view {
        uint16 retrivedQuantity = uint16(voucher.tokenId & 0xFFFF);
        if (voucher.price <= 0) {
            revert InvalidPrice(voucher.tokenId, voucher.price);
        }
        if (voucher.quantity < 1) {
            revert InvalidTokenQty(voucher.tokenId, retrivedQuantity, voucher.quantity);
        }
        if (voucher.quantity != retrivedQuantity) {
            revert InvalidTokenQty(voucher.tokenId, retrivedQuantity, voucher.quantity);
        }
        if (voucher.buyerQty > retrivedQuantity) {
            revert InvalidTokenQty(voucher.tokenId, retrivedQuantity, voucher.buyerQty);
        }

        uint256 tokenQty = tokenMaxQty[voucher.tokenId];
        if (tokenQty > 0) {
            uint256 tokensMinted = tokenMintedQty[voucher.tokenId];
            if (tokensMinted + voucher.buyerQty > tokenQty) {
                revert InvalidTokenQty(voucher.tokenId, tokensMinted, tokensMinted + voucher.buyerQty);
            }
        }
    }

    function _verifySignatures(NFTVoucher calldata voucher) internal view returns (address) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "NFTVoucher(uint256 tokenId,uint256 price,uint256 quantity,uint256 buyerQty,uint256 start,uint256 end,uint96 royalty,bool isStealth,bool isSbt)"
                    ),
                    voucher.tokenId,
                    voucher.price,
                    voucher.quantity,
                    voucher.buyerQty,
                    voucher.start,
                    voucher.end,
                    voucher.royalty,
                    voucher.isStealth,
                    voucher.isSbt
                )
            )
        );

        address creator = ECDSA.recover(digest, voucher.creator);
        if (voucher.tokenId >> 96 != uint256(uint160(creator))) {
            revert InvalidSender(creator);
        }

        address validator = ECDSA.recover(digest, voucher.validator);
        if (!hasRole(MINT_VALIDATOR_ROLE, validator)) {
            revert AccessDenied(MINT_VALIDATOR_ROLE, validator);
        }

        return creator;
    }

    /* URI MANEGEMENT */
    /// @notice Returns the URI to the token's metadata.
    /// @param tokenId Nft token id.
    function uri(uint256 tokenId) public view override returns (string memory) {
        if (stealth[tokenId]) {
            return bytes(stealthUri).length > 0 ? string(abi.encodePacked(stealthUri)) : "";
        }
        if (!uriSuffixEnabled) {
            return bytes(baseUri).length > 0 ? string(abi.encodePacked(baseUri, tokenId.toString())) : "";
        }
        return bytes(baseUri).length > 0 ? string(abi.encodePacked(baseUri, tokenId.toString(), uriSuffix)) : "";
    }

    /// @notice Update the baseURI.
    /// @param newBaseUri New collection uri.
    function updateBaseUri(string memory newBaseUri) external onlyRole(MANAGER_ROLE) {
        baseUri = newBaseUri;
    }

    /// @notice Update stealth NFT URI.
    /// @param newStealthUri New stealth URI.
    function updateStealthUri(string memory newStealthUri) external onlyRole(MANAGER_ROLE) {
        stealthUri = newStealthUri;
    }

    /// @notice Update URI's base extention.
    /// @param newSuffix New base uri extention.
    function updateUriSuffix(string memory newSuffix) external onlyRole(MANAGER_ROLE) {
        uriSuffix = newSuffix;
    }

    /// @notice Flips the flag to use UriSuffix.
    function toggleUriSuffix() external onlyRole(MANAGER_ROLE) {
        uriSuffixEnabled = !uriSuffixEnabled;
    }

    /* SBT - SOUL BOUND TOKENS - NON TRANSFERABLE */

    function locked(uint256 tokenId) external view returns (bool) {
        if (sbt[tokenId]) return true;
        return false;
    }

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        virtual
        override
    {
        for (uint256 i = 0; i < ids.length; ++i) {
            if (to != address(0)) {
                if (sbt[ids[i]] && !hasRole(REFUND_MANAGER_ROLE, msg.sender)) {
                    revert NonTransferableToken();
                }
            }
        }
        return super._update(from, to, ids, values);
    }

    function burn(uint256 tokenId, uint256 quantity) external {
        if (balanceOf(msg.sender, tokenId) < quantity) {
            revert InsufficientBalance();
        }
        _burn(msg.sender, tokenId, quantity);
        tokenMaxQty[tokenId] -= quantity;
        tokenMintedQty[tokenId] -= quantity;
        if (tokenMaxQty[tokenId] == 0) {
            creatorRegistry[tokenId] = address(0);
        }
        emit Burnt(tokenId, quantity);
    }

    /* REFUND */

    /// @notice Refund an NFT back to creator.
    /// @dev Can only be performed by REFUND_MANAGER
    /// @param tokenId The tokenID of the NFT which needs to be refunded.
    /// @param creator The creator of the NFT.
    /// @param owner Current owner of the NFT.
    /// @param qty How many of this NFT to refund.
    function refundNFT(uint256 tokenId, address creator, address owner, uint256 qty)
        external
        onlyRole(REFUND_MANAGER_ROLE)
    {
        if (creatorRegistry[tokenId] != creator) {
            revert NotTokenCreator(creator, tokenId);
        }
        if (balanceOf(owner, tokenId) < qty) {
            revert NotTokenOwner(owner, tokenId, qty);
        }
        safeTransferFrom(owner, creator, tokenId, qty, "");
        emit Refunded(tokenId, owner, qty);
    }

    /// @dev Override to allow refund.
    function isApprovedForAll(address account, address operator) public view override returns (bool) {
        if (approvedContracts[operator]) {
            return true;
        }
        if (hasRole(REFUND_MANAGER_ROLE, operator)) {
            return true;
        }

        return super.isApprovedForAll(account, operator);
    }

    /* PIONEER MANAGEMENT */

    /// @notice Grant wallet pioneer status.
    /// @param pioneer The pioneer wallet.
    function addPioneer(address pioneer) external onlyRole(AGENCY_MANAGER_ROLE) {
        if (pioneers[pioneer]) revert AlreadyAdded(pioneer);
        pioneers[pioneer] = true;
    }

    /* AGENCY MANAGEMENT */

    /// @notice Add an agency and specify their fee.
    /// @param agency The agency wallet.
    /// @param fee The fee for the agency.
    function addAgency(address agency, uint256 fee) external onlyRole(AGENCY_MANAGER_ROLE) {
        if (agencyFee[agency] > 0) revert AlreadyAdded(agency);
        agencyFee[agency] = fee;
    }

    /// @notice To add the creator wallet corresponding to their agency.
    /// @param agency The agency wallet.
    /// @param creators Creator wallets to be added as creators of this agency.
    function addCreator(address agency, address[] memory creators) external onlyRole(AGENCY_MANAGER_ROLE) {
        for (uint256 i = 0; i < creators.length; i++) {
            // TODO: Maybe convert this to a skip, rather than a revert?
            if (agencyCreator[creators[i]] != address(0)) {
                revert AlreadyAdded(creators[i]);
            }
            agencyCreator[creators[i]] = agency;
        }
    }

    /* PRE-APPROVED CONTRACTS */

    /// @notice dappunk pre-approved contracts.
    /// @dev reduce dappunk creators gas by not requiring approval for this contract.
    /// @param contractAddress The contract to set as approved.
    function setApprovedContract(address contractAddress) public onlyRole(CONTRACT_APPROVER_ROLE) {
        if (approvedContracts[contractAddress]) {
            revert AlreadyAdded(contractAddress);
        }
        approvedContracts[contractAddress] = true;
    }

    /// @notice Removes a pre-approved contracts.
    /// @param contractAddress The contract no longer be approved.
    function removeApprovedContract(address contractAddress) public onlyRole(CONTRACT_APPROVER_ROLE) {
        // require(approvedContracts[contractAddress], "DoesntExist: Contract not approved");
        if (!approvedContracts[contractAddress]) {
            revert NotSupported(contractAddress);
        }
        approvedContracts[contractAddress] = false;
    }

    /* CONTRACT STATE */
    function deprecate() external deprecated onlyRole(DEFAULT_ADMIN_ROLE) {
        isDeprecated = true;
    }

    function reviveContract() external onlyRole(DEFAULT_ADMIN_ROLE) {
        isDeprecated = false;
    }

    /* FUND MANAGEMENT */

    /// @notice Add an erc20 token support for payment.
    /// @param tokenAddress Address of ERC20 token contract.
    function addSupportedToken(address tokenAddress) external onlyRole(MANAGER_ROLE) {
        if (supportedTokens[tokenAddress]) revert AlreadyAdded(tokenAddress);
        supportedTokens[tokenAddress] = true;
    }

    /// @notice Remove an ERC20 token support for payment.
    /// @param tokenAddress Address of ERC20 token contract.
    function removeSupportedToken(address tokenAddress) external onlyRole(MANAGER_ROLE) {
        if (!supportedTokens[tokenAddress]) revert NotSupported(tokenAddress);
        supportedTokens[tokenAddress] = false;
    }

    /// @notice Withdraw all of the platform native currency from contract.
    function withdraw() external onlyRole(FUND_MANAGER_ROLE) {
        Address.sendValue(payable(msg.sender), address(this).balance);
    }

    /// @notice Withdraw all of a token from contract.
    /// @param tokenAddress Address of ERC20 token contract.
    function withdraw(address tokenAddress) external onlyRole(FUND_MANAGER_ROLE) {
        if (!supportedTokens[tokenAddress]) revert NotSupported(tokenAddress);
        IERC20 token = IERC20(tokenAddress);
        bool success = token.transfer(msg.sender, token.balanceOf(address(this)));
        if (!success) revert TransferError();
    }

    /// @dev See {IERC165-supportsInterface}.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, ERC2981, AccessControl, CCIPReceiver)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function setApprovalForAll(address operator, bool approved) public override {
        if (hasRole(MARKET_PLACE, msg.sender)) {
            _setApprovalForAll(operator, msg.sender, approved);
        } else {
            _setApprovalForAll(_msgSender(), operator, approved);
        }
    }

    function _msgSender() internal view override(Context, ERC2771Context) returns (address) {
        if (isTrustedForwarder(msg.sender)) {
            return ERC2771Context._msgSender();
        } else {
            return Context._msgSender();
        }
    }

    function _msgData() internal view override(Context, ERC2771Context) returns (bytes calldata) {
        if (isTrustedForwarder(msg.sender)) {
            return ERC2771Context._msgData();
        } else {
            return Context._msgData();
        }
    }

    function _contextSuffixLength() internal view override(Context, ERC2771Context) returns (uint256) {
        if (isTrustedForwarder(msg.sender)) {
            return ERC2771Context._contextSuffixLength();
        } else {
            return Context._contextSuffixLength();
        }
    }

    receive() external payable {}

    // build the ccip message

    // interact with the Router and send the CCIP message

    // Override and build CCIPReceive
    /*
        struct EVMTokenAmount {
            address token; // token address on the local chain.
            uint256 amount; // Amount of tokens.
        }

        struct Any2EVMMessage {
            bytes32 messageId; // MessageId corresponding to ccipSend on source.
            uint64 sourceChainSelector; // Source chain selector.
            bytes sender; // abi.decode(sender) if coming from an EVM chain.
            bytes data; // payload sent in original message.
            EVMTokenAmount[] destTokenAmounts; // Tokens and their amounts in their destination chain representation.
        }
    
    */

    function _ccipReceive(Client.Any2EVMMessage memory message) internal override {
        // specify the logic here of what you want to do when you receive a message
        // mint logic inhere
        crossChainReceive memory receivedVoucher = abi.decode(message.data, (crossChainReceive));
        if (balanceOf(receivedVoucher.creator, receivedVoucher.tokenId) != 0) revert(); // to avoid collisions on channels
        // set royality
        // set tokenMaxQty
        // Increase the minted Qty
    }
}
