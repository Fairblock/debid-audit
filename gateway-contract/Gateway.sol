// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IGateway} from "./IGateway.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title Gateway
/// @author Fairblock
/// @notice The Gateway contract is the main entry point for FairyPort to submit decryption keys and FIDs.
contract Gateway is IGateway, Context, Ownable {

    event RequestGeneralID(address indexed requester, uint256 id);
    event RequestGeneralKey(address indexed requester, uint256 id);

    /// @notice Emitted when a FID is submitted to the Gateway contract
    /// @param _requester the specific requesting address that created the general ID
    /// @param fid the unique FairyRing ID
    /// @param id the general ID sequence number for this specific requester's request
    event FIDSubmitted(address indexed _requester, string indexed fid, uint256 indexed id);


    uint256 generalRequestFee = 0;
    
    bytes public latestEncryptionKey;
    mapping(bytes => bool) public encryptionKeyExists;

    mapping(uint256 => bytes) public decryptionKeys;
    uint256 latestDecryptionKeyHeight = 0;

    mapping(address =>  uint256) public addressGeneralID;
    mapping(address => mapping(uint256 => bool)) public generalIDRequested;
    mapping(address => mapping(uint256 => bool)) public generalKeyRequested;
    mapping(address => mapping(uint256 => string)) public fids;
    mapping(address => mapping(uint256 => bytes)) public generalDecryptionKeys;


    constructor() Ownable(_msgSender()) {}

    /// @notice FairyPort submits new encryption key
    /// @param encryptionKey the master public key relayed by FairyPort ultimately from FairyRing
    function submitEncryptionKey(
        bytes memory encryptionKey
    ) external onlyOwner() {
        require(!encryptionKeyExists[encryptionKey], "encryption key already exists");
        latestEncryptionKey = encryptionKey;
        encryptionKeyExists[encryptionKey] = true;
    }

    /// @notice FairyPort submits decryption key based on block height
    /// @param encryptionKey the master public key relayed by FairyPort ultimately from FairyRing
    /// @param decryptionKey the specific decryption key relayed by FairyPort ultimately from FairyRing
    /// @param height the block height specified for the respective tx to be decrypted at, that also serves as the ID used for encryption
    /// @dev this is instigated by a FairyPort deployment
    function submitDecryptionKey(
        bytes memory encryptionKey,
        bytes memory decryptionKey,
        uint256 height
    ) external onlyOwner() {
        require(decryptionKeys[height].length == 0, "decryption key for given height already exists");
        require(encryptionKeyExists[encryptionKey], "encryption key does not exists");

        decryptionKeys[height] = decryptionKey;
        latestDecryptionKeyHeight = height;
    }

    /// @notice FairyPort submits decryption key based on a general ID, which follows a different tx flow than encrypted txs based on block-height-based ID
    /// @param requester the specific requesting address that created the general ID request
    /// @param id the general ID sequence number for a specific requester
    /// @param decryptionKey the specific decryption key relayed by FairyPort ultimately from FairyRing
    /// @dev this is instigated by a FairyPort deployment
    function submitGeneralDecryptionKeys(
        address requester,
        uint256 id,
        bytes memory decryptionKey
    ) external onlyOwner() {
        require(generalIDRequested[requester][id], "The given requester & ID have not requested the general identity");
        require(generalKeyRequested[requester][id], "The given requester & ID have not requested the general decryption key");
        require(generalDecryptionKeys[requester][id].length == 0, "Decryption key for the given requester & ID already exists");
        
        generalDecryptionKeys[requester][id] = decryptionKey;
   }

    /// @notice FairyPort submits FID to be stored in Gateway contract
    /// @param _requester the specific requesting address that created the general ID request
    /// @param _fid the unique FairyRing ID relayed by FairyPort for the requester's request
    /// @param _id the general ID sequence number for this specific requester's request
    function submitFID(address _requester, string memory _fid, uint256 _id) external onlyOwner {
        require(generalIDRequested[_requester][_id], "The given requester & ID have not requested the general identity");

        fids[_requester][_id] = _fid;

        emit FIDSubmitted(_requester, _fid, _id);

    }

    /// @notice A requester can request a general decryption key for a specific general ID
    /// @param id the general ID sequence number for this specific requester's request
    function requestGeneralDecryptionKey(uint256 id) external {
        require(generalIDRequested[_msgSender()][id], "Given ID is not requested");
        require(!generalKeyRequested[_msgSender()][id], "Already request decryption key for the given ID");
        generalKeyRequested[_msgSender()][id] = true;
        emit RequestGeneralKey(_msgSender(), id);
    }
    // @notice A requester can request a general ID, the sequence number of the requester is incremented by 1 each time
    function requestGeneralID() external {
        uint256 id = addressGeneralID[_msgSender()];
        generalIDRequested[_msgSender()][id] = true;
        addressGeneralID[_msgSender()] = addressGeneralID[_msgSender()] + 1;
        emit RequestGeneralID(_msgSender(), id);
    }

    function setRequestGeneralFee(uint256 newFee) external onlyOwner() {
        generalRequestFee = newFee;
    }   

    function getRandomnessByHeight(uint256 height) external view returns (bytes32) {
        return _getDecryptionKey(height);
    }

    function latestRandomnessHashOnly() external view returns (bytes32) {
        return _getDecryptionKey(latestDecryptionKeyHeight);
    }

    function latestRandomness() external view returns (bytes32, uint256) {
        return (_getDecryptionKey(latestDecryptionKeyHeight), latestDecryptionKeyHeight);
    }
    /// @notice Returns the decryption key for a given block height
    /// @param height the block height specified for which the decryption key is requested
    function _getDecryptionKey(uint256 height) internal view returns (bytes32) {
         if (decryptionKeys[height].length == 0) {
            return bytes32(0);
        } else {
            return keccak256(decryptionKeys[height]);
        }
    }
}
