pragma solidity ^0.8.0;

interface IDecrypter {
    function decrypt(uint8[] memory c, uint8[] memory skbytes) external returns (uint8[] memory);
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
        uint256 bidCondition; // blockheight
        uint256 auctionFee;
        uint256 highestBid;
        address highestBidder;
        bool auctionFinalized; // just an indicator
        BidEntry[] bids; // array of bid structs, where values are defined too. Ex.) `bids[1].bidValue` would be undefined until the auction is over
        string fairyRingID; // single FID for entire auction
        uint256 gatewayID; // ID sequence for details from Gateway
    }

    mapping(uint256 => Auction) public auctions;
    uint256 public auctionCounter; // just to show how many auctions we are at.

    event AuctionCreated(uint256 auctionId, uint256 deadline, uint256 fee);
    event BidSubmitted(uint256 auctionId, address bidder, uint256 bidIndex);
    event AuctionFinalized(uint256 auctionId, address winner, uint256 winningBid);
    event RefundIssued(uint256 auctionId, address bidder, uint256 amount);
    event ContractInitialized(address decrypter);

    /**
     * @notice Sets the auction with a decryption contract
     * @param _decrypter Address of the decryption contract
     */
    constructor(address _decrypter) {
        decrypterContract = IDecrypter(_decrypter);
        emit ContractInitialized(_decrypter);
    }

    function createAuction(uint256 _deadline, uint256 _fee, string memory _fairyRingID, uint256 _gatewayID) external {
        auctionCounter++;

        Auction storage newAuction = auctions[auctionCounter];
        newAuction.auctionOwner = msg.sender;
        newAuction.bidCondition = _deadline;
        newAuction.auctionFee = _fee;
        newAuction.highestBid = 0;
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
    function submitEncryptedBid(uint256 auctionId, uint8[] calldata encryptedBid) external payable {
        Auction storage auction = auctions[auctionId];
      //  require(block.timestamp <= auction.bidCondition, "Auction deadline passed");
        require(msg.value >= auction.auctionFee, "Insufficient fee");

        auction.bids.push(
            BidEntry({bidder: msg.sender, encryptedBid: encryptedBid, isDecrypted: false, bidValue: msg.value})
        );

        emit BidSubmitted(auctionId, msg.sender, auction.bids.length - 1);
    }

    /// @dev This function would be called by the FE (bash script) after the auction deadline has passed, and the decryption key is available. It will decrypt all bids, find the highest bid, and finalize the auction.
   function revealBids(uint256 auctionId, uint8[] memory decryptionKey, uint256 decryptInThisCall) external {
        Auction storage auction = auctions[auctionId];
       // require(block.timestamp >= auction.bidCondition, "Auction still ongoing");
        require(!auction.auctionFinalized, "Auction already finalized");

        
        uint256 decryptedThisCall = 0;
        for (uint256 i = 0; i < auction.bids.length && decryptedThisCall < decryptInThisCall; i++) {
            if (!auction.bids[i].isDecrypted) {
                uint8[] memory out = decrypterContract.decrypt(
                    auction.bids[i].encryptedBid,
                    decryptionKey
                );
                auction.bids[i].isDecrypted = true;
                uint256 bidValue = uint8ArrayToUint256(out);
                auction.bids[i].bidValue = bidValue;
                decryptedThisCall++;
            }
        }


        bool allDecrypted = true;
        for (uint256 i = 0; i < auction.bids.length; i++) {
            if (!auction.bids[i].isDecrypted) {
                allDecrypted = false;
                break;
            }
        }

      
        if (allDecrypted) {
            uint256 highestBidLocal = 0;
            address highestBidderLocal = address(0);

            for (uint256 i = 0; i < auction.bids.length; i++) {
                uint256 bidValue = auction.bids[i].bidValue;

                if (bidValue > highestBidLocal) {
                    highestBidLocal = bidValue;
                    highestBidderLocal = auction.bids[i].bidder;
                }
            }

            auction.highestBid = highestBidLocal;
            auction.highestBidder = highestBidderLocal;
            auction.auctionFinalized = true;


            emit AuctionFinalized(auctionId, highestBidderLocal, highestBidLocal);
        }
    }


    function isFinalized(uint256 auctionId) external view returns (bool){
        return  auctions[auctionId].auctionFinalized;
    }

    function uint8ArrayToUint256(uint8[] memory arr) public pure returns (uint256 result) {
        for (uint256 i = 0; i < arr.length; i++) {
            require(arr[i] >= 48 && arr[i] <= 57, "Invalid character in input");
            result = result * 10 + (arr[i] - 48);
        }
    }
}

