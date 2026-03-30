pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IDecrypter {
    function decrypt(uint8[] memory c, uint8[] memory skbytes) external returns (uint8[] memory);
}

interface IGateway {
    function generalIDRequested(address requester, uint256 id) external view returns (bool);
    function generalKeyRequested(address requester, uint256 id) external view returns (bool);
    function fids(address requester, uint256 id) external view returns (string memory);
    function generalDecryptionKeys(address requester, uint256 id) external view returns (bytes memory);
}

/**
 * @title Simple Sealed Bid Multi-Auction Example
 * @notice Example Auction App where multiple auctions are housed within one contract.
 * @dev Each auction acts as follows: a sealed-bid auction where bids are submitted encrypted and revealed using a decryption key once a certain time is passed, triggering the end of the auction. The auctionOwner gets the bid amount; this is assuming that the auction is tied to some offchain deliverable (Art auction etc.).
 * Mapping of auctions (struct) are core to this contract.
 * @dev tx flow, as seen in README, involves MultiAuction.sol interacting with Gateway.sol on respective network to obtain unique id corresponding to FairyRing IDs (FIDs) stored in Gateway.sol
 * @dev This is purely for educational purposes and is not ready for production. Developers must carry out their own due diligence when it comes to deployment of smart contracts in production, including but not limited to, thorough audits, secure design practices, etc.
 */
contract MultiAuction {
    /// @notice Reference to an external decryption contract
    IDecrypter public decrypterContract;

    struct BidEntry {
        address bidder;
        uint8[] encryptedBid;
        bool isDecrypted;
        uint256 bidValue;
    }

    struct Auction {
        address auctionOwner;
        uint256 bidCondition; // deadline timestamp (Unix seconds)
        uint256 auctionFee;
        uint256 collectedFees; // total ETH received from submitEncryptedBid for this auction
        uint256 highestBid;
        address highestBidder;
        bool auctionFinalized; // just an indicator
        BidEntry[] bids; // array of bid structs, where values are defined too. Ex.) `bids[1].bidValue` would be undefined until the auction is over
        string fairyRingID; // single FID for entire auction
        uint256 gatewayID; // ID sequence for details from Gateway
        uint256 nextIndexToScan; // progress cursor to avoid rescanning already-processed bids
        uint8[] decryptionKey; // decryption key for the auction
    }

    mapping(uint256 => Auction) public auctions;
    uint256 public auctionCounter; // just to show how many auctions we are at.
    uint256 public constant MAX_CIPHERTEXT_LEN = 8192;
    address public gateway;
    mapping(address => uint256) public pendingFees;
    event AuctionCreated(uint256 auctionId, uint256 deadline, uint256 fee);
    event BidSubmitted(uint256 auctionId, address bidder, uint256 bidIndex);
    event AuctionFinalized(uint256 auctionId, address winner, uint256 winningBid);
    event RefundIssued(uint256 auctionId, address bidder, uint256 amount);
    event ContractInitialized(address decrypter);

    /// @notice Check if the address is a contract
    function _isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    /// @notice Reverts that mean the ciphertext or parsed structure is invalid; safe to mark bid as zero.
    function _isBadBidError(bytes32 r) internal pure returns (bool) {
        return
            r == keccak256("MAC_MISMATCH") ||
            r == keccak256("Verfication failed") ||
            r == keccak256("Invalid input length") ||
            r == keccak256("Wrong input length") ||
            r == keccak256("BAD_HDR") ||
            r == keccak256("PARSE_ERR") ||
            r == keccak256("BAD_G1") ||
            r == keccak256("LEN_ERR") ||
            r == keccak256("CIPH_SHORT") ||
            r == keccak256("C_TOO_LARGE") ||
            r == keccak256("BAD_G2_LEN") ||
            r == keccak256("BAD_G2") ||
            r == keccak256("BAD_MAC_LEN");
    }

    /// @notice Reverts from helper subcalls or environment; may succeed if retried with sufficient gas / correct setup.
    function _isTransientError(bytes32 r) internal pure returns (bool) {
        return
            r == keccak256("MAC_ERR") ||
            r == keccak256("C20_ERR") ||
            r == keccak256("Hasher error") ||
            r == keccak256("PAYLOAD_ERR") ||
            r == keccak256("NOT_INIT") ||
            r == keccak256("Contract not initialized") ||
            r == keccak256("NO_VALUE") ||
            r == keccak256("Error deserializing the scalar") ||
            r == keccak256("Hashing error") ||
            r == keccak256("decryption error") ||
            r == keccak256("Key error") ||
            r == keccak256("Hash error") ||
            r == keccak256("Header error");
    }
    /**
     * @notice Sets the auction with a decryption contract
     * @param _decrypter Address of the decryption contract
     */
    constructor(address _decrypter, address _gateway) {
        require(_decrypter != address(0), "Invalid decryption contract");
        require(_isContract(_decrypter), "Invalid decrypter: not contract");
        require(_gateway != address(0), "Invalid gateway");
        require(_isContract(_gateway), "Invalid gateway: not contract");
        decrypterContract = IDecrypter(_decrypter);
        gateway = _gateway;
        emit ContractInitialized(_decrypter);
    }

    function createAuction(uint256 _deadline, uint256 _fee, string memory _fairyRingID, uint256 _gatewayID) external {
        require(_deadline > block.timestamp, "Deadline must be in the future");
        require(IGateway(gateway).generalIDRequested(msg.sender, _gatewayID), "ID not requested");
        require(IGateway(gateway).generalKeyRequested(msg.sender, _gatewayID), "Key not requested");
        string memory fid = IGateway(gateway).fids(msg.sender, _gatewayID);
        require(bytes(fid).length != 0, "FID not set");
        require(keccak256(bytes(_fairyRingID)) == keccak256(bytes(fid)), "FID mismatch");
        auctionCounter++;

        Auction storage newAuction = auctions[auctionCounter];
        delete newAuction.bids; // ensure no inherited bids from pre-existing writes to this slot
        newAuction.auctionOwner = msg.sender;
        newAuction.bidCondition = _deadline;
        newAuction.auctionFee = _fee;
        newAuction.highestBid = 0;
        newAuction.collectedFees = 0;
        newAuction.highestBidder = address(0);
        newAuction.auctionFinalized = false;
        newAuction.fairyRingID = _fairyRingID;
        newAuction.gatewayID = _gatewayID;

        emit AuctionCreated(auctionCounter, _deadline, _fee);
    }

    /// @notice Submit encrypted bid (cyphertext) to respective auction.
    /// @param auctionId Unique auction ID bid is associated with
    /// @param encryptedBid Cyphertext generated using FairyRing `encrypter` with FID and MPK
    /// @dev There is one FID per auction. So once auction is over, all bids are decrypted using decryption key for respective Auction FID.
    function submitEncryptedBid(uint256 auctionId, uint8[] calldata encryptedBid, bytes calldata sig) external payable {
        require(auctionId > 0 && auctionId <= auctionCounter, "Invalid auction");
        Auction storage auction = auctions[auctionId];
        require(auction.auctionOwner != address(0), "Invalid auction");
        require(!auction.auctionFinalized, "Auction finalized");
        require(block.timestamp < auction.bidCondition, "Auction deadline passed");
        require(IGateway(gateway).generalDecryptionKeys(auction.auctionOwner, auction.gatewayID).length == 0, "Bidding closed: decryption key posted");
        require(msg.value >= auction.auctionFee, "Insufficient fee");
        require(encryptedBid.length > 0 && encryptedBid.length <= MAX_CIPHERTEXT_LEN, "Invalid ciphertext size");

        bytes32 cHash = keccak256(abi.encodePacked(encryptedBid));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            keccak256(abi.encode(auctionId, cHash, msg.sender, address(this), block.chainid))
        );
        require(ECDSA.recover(digest, sig) == msg.sender, "invalid bid signature");

        auction.collectedFees += msg.value;

        auction.bids.push(
            BidEntry({bidder: msg.sender, encryptedBid: encryptedBid, isDecrypted: false, bidValue: 0})
        );

        emit BidSubmitted(auctionId, msg.sender, auction.bids.length - 1);
    }

    /// @dev This function would be called by the FE (bash script) after the auction deadline has passed, and the decryption key is available. It will decrypt all bids, find the highest bid, and finalize the auction.
   function revealBids(uint256 auctionId, uint256 decryptInThisCall) external {
        require(auctionId > 0 && auctionId <= auctionCounter, "Invalid auction");
        Auction storage auction = auctions[auctionId];
        require(auction.auctionOwner != address(0), "Invalid auction");
        require(block.timestamp >= auction.bidCondition, "Auction still ongoing");
        require(!auction.auctionFinalized, "Auction already finalized");
        if (auction.decryptionKey.length == 0 && auction.nextIndexToScan < auction.bids.length) {
        bytes memory key = IGateway(gateway).generalDecryptionKeys(auction.auctionOwner,auction.gatewayID);
        require(key.length == 96, "Decryption key not found");
        auction.decryptionKey = toUint8Array(key);
        }
        
        uint256 decryptedThisCall = 0;
        uint256 i = auction.nextIndexToScan;
        for (i = auction.nextIndexToScan; i < auction.bids.length && decryptedThisCall < decryptInThisCall; i++) {
            if (!auction.bids[i].isDecrypted) {
                if (auction.bids[i].encryptedBid.length == 0 || auction.bids[i].encryptedBid.length > MAX_CIPHERTEXT_LEN) {
                    auction.bids[i].isDecrypted = true;
                    auction.bids[i].bidValue = 0;
                    decryptedThisCall++;
                    continue;
                }
                try decrypterContract.decrypt(
                    auction.bids[i].encryptedBid,
                    auction.decryptionKey
                ) returns (uint8[] memory out) {
                    auction.bids[i].isDecrypted = true;
                    uint256 bidValue = uint8ArrayToUint256(out);
                    auction.bids[i].bidValue = bidValue;
                    if (bidValue > auction.highestBid) {
                        auction.highestBid = bidValue;
                        auction.highestBidder = auction.bids[i].bidder;
                    }
                } catch (bytes memory reason) {
                    if (reason.length == 0) {
                        break;
                    }
                    bytes32 r = keccak256(reason);
                    if (_isBadBidError(r)) {
                        auction.bids[i].isDecrypted = true;
                        auction.bids[i].bidValue = 0;
                    } else if (_isTransientError(r)) {
                        break;
                    } else {
                        break;
                    }
                }
                decryptedThisCall++;
            }
        }
        auction.nextIndexToScan = i;


        bool allDecrypted = true;
        for (uint256 j = auction.nextIndexToScan; j < auction.bids.length; j++) {
            if (!auction.bids[j].isDecrypted) {
                allDecrypted = false;
                break;
            }
        }

      
        if (allDecrypted) {
            auction.auctionFinalized = true;
            uint256 fees = auction.collectedFees;
            auction.collectedFees = 0;
            if (fees > 0) {
                (bool success, ) = payable(auction.auctionOwner).call{value: fees}("");
                if (!success) { pendingFees[auction.auctionOwner] += fees; }
            }
            emit AuctionFinalized(auctionId, auction.highestBidder, auction.highestBid);
        }
    }
    function withdrawFees(uint256 amount) external {
        require(amount > 0 && pendingFees[msg.sender] >= amount, "invalid amount");
        unchecked { pendingFees[msg.sender] -= amount; }
        (bool s, ) = payable(msg.sender).call{value: amount}("");
        require(s, "withdraw failed");
    }

    function isFinalized(uint256 auctionId) external view returns (bool){
        return  auctions[auctionId].auctionFinalized;
    }

    function uint8ArrayToUint256(uint8[] memory arr) public pure returns (uint256 result) {
        uint256 start = 0;
        uint256 end = arr.length;
        while (start < end && (arr[start] == 32 || arr[start] == 9 || arr[start] == 10 || arr[start] == 13)) start++;
        while (end > start && (arr[end - 1] == 32 || arr[end - 1] == 9 || arr[end - 1] == 10 || arr[end - 1] == 13)) end--;
        if (end <= start || end - start > 78) return 0;
        for (uint256 i = start; i < end; i++) {
            uint8 b = arr[i];
            if (b < 48 || b > 57) return 0;
            uint256 digit = uint256(b - 48);
            if (result > (type(uint256).max - digit) / 10) return 0;
            unchecked {
                result = result * 10 + digit;
            }
        }
    }
    function toUint8Array(bytes memory b) public pure returns (uint8[] memory) {
        uint8[] memory result = new uint8[](b.length);
        for (uint256 i = 0; i < b.length; i++) {
            result[i] = uint8(b[i]);
        }
        return result;
    }
    function stringToUint(string memory s) public pure returns (uint256) {
        return uint8ArrayToUint256(toUint8Array(bytes(s)));
    }
}

