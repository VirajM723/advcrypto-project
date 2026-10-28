// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ValidatorGovernance
/// @notice On-chain voting over the active validator set. Exposes
///         getValidators(), the interface Hyperledger Besu's QBFT reads when
///         configured with `validatorcontractaddress`, so a vote executed in
///         block h changes who may seal from block h+1.
/// @dev    Solidity twin of poa/contract.py; both follow the same rules.
contract ValidatorGovernance {
    enum Kind { Add, Remove }
    enum Status { Pending, Executed, Rejected, Expired, Cancelled, Failed }

    struct Proposal {
        Kind kind;
        address subject;
        address proposer;
        uint64 createdAt;
        uint64 expiresAt;
        Status status;
        address[] yesVoters;
        address[] noVoters;
    }

    uint8 public immutable quorumPct;      // passes when yes*100 > n*quorumPct
    uint64 public immutable votePeriod;    // blocks a proposal stays open
    uint32 public immutable minValidators;
    uint32 public immutable maxValidators;

    address[] private validators;
    mapping(address => bool) public isValidator;

    uint256 public nextId = 1;
    mapping(uint256 => Proposal) private proposals;
    mapping(bytes32 => uint256) public openProposal; // keccak(kind, subject) => id
    // 0 = none, 1 = yes, 2 = no
    mapping(uint256 => mapping(address => uint8)) public voteOf;

    event ProposalCreated(uint256 indexed id, Kind kind, address indexed subject, address indexed proposer);
    event VoteCast(uint256 indexed id, address indexed voter, bool support);
    event ProposalClosed(uint256 indexed id, Status status);
    event ValidatorAdded(address indexed validator, uint256 blockNumber);
    event ValidatorRemoved(address indexed validator, uint256 blockNumber);

    error NotValidator();
    error InvalidSubject();
    error BoundsViolated();
    error AlreadyOpen();
    error NotOpen();
    error Expired();
    error NotProposer();

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert NotValidator();
        _;
    }

    constructor(address[] memory initial, uint8 _quorumPct, uint64 _votePeriod, uint32 _min, uint32 _max) {
        require(_quorumPct < 100, "quorumPct");
        require(_min >= 1 && _min <= initial.length && initial.length <= _max, "bounds");
        quorumPct = _quorumPct;
        votePeriod = _votePeriod;
        minValidators = _min;
        maxValidators = _max;
        for (uint256 i = 0; i < initial.length; i++) {
            require(initial[i] != address(0) && !isValidator[initial[i]], "dup");
            isValidator[initial[i]] = true;
            validators.push(initial[i]);
        }
    }

    // ------------------------------------------------------------------ views

    function getValidators() external view returns (address[] memory) {
        return validators;
    }

    function requiredVotes() public view returns (uint256) {
        return validators.length * quorumPct / 100 + 1;
    }

    function getProposal(uint256 id)
        external
        view
        returns (Kind kind, address subject, address proposer, uint64 expiresAt, Status status, uint256 yes, uint256 no)
    {
        Proposal storage p = proposals[id];
        status = _isExpired(p) ? Status.Expired : p.status;
        (yes, no) = _count(p);
        return (p.kind, p.subject, p.proposer, p.expiresAt, status, yes, no);
    }

    // --------------------------------------------------------------- mutating

    function propose(Kind kind, address subject) external onlyValidator returns (uint256 id) {
        if (subject == address(0)) revert InvalidSubject();
        if (kind == Kind.Add) {
            if (isValidator[subject]) revert InvalidSubject();
            if (validators.length >= maxValidators) revert BoundsViolated();
        } else {
            if (!isValidator[subject]) revert InvalidSubject();
            if (validators.length <= minValidators) revert BoundsViolated();
        }

        bytes32 key = keccak256(abi.encode(kind, subject));
        uint256 existing = openProposal[key];
        if (existing != 0) {
            if (!_isExpired(proposals[existing])) revert AlreadyOpen();
            _close(existing, Status.Expired);
        }

        id = nextId++;
        Proposal storage p = proposals[id];
        p.kind = kind;
        p.subject = subject;
        p.proposer = msg.sender;
        p.createdAt = uint64(block.number);
        p.expiresAt = uint64(block.number) + votePeriod;
        p.status = Status.Pending;
        openProposal[key] = id;
        emit ProposalCreated(id, kind, subject, msg.sender);
        _cast(id, true);
    }

    function vote(uint256 id, bool support) external onlyValidator returns (Status) {
        return _cast(id, support);
    }

    /// @notice Re-tally, e.g. after a removal lowered the required vote count.
    function execute(uint256 id) external onlyValidator returns (Status) {
        _requireOpen(id);
        return _tally(id);
    }

    function cancel(uint256 id) external {
        _requireOpen(id);
        if (proposals[id].proposer != msg.sender) revert NotProposer();
        _close(id, Status.Cancelled);
    }

    // -------------------------------------------------------------- internals

    function _isExpired(Proposal storage p) private view returns (bool) {
        return p.status == Status.Pending && block.number > p.expiresAt;
    }

    function _requireOpen(uint256 id) private view {
        Proposal storage p = proposals[id];
        if (p.proposer == address(0) || p.status != Status.Pending) revert NotOpen();
        if (_isExpired(p)) revert Expired();
    }

    function _cast(uint256 id, bool support) private returns (Status) {
        _requireOpen(id);
        Proposal storage p = proposals[id];
        uint8 prev = voteOf[id][msg.sender];
        if (prev == 1) _removeFrom(p.yesVoters, msg.sender);
        else if (prev == 2) _removeFrom(p.noVoters, msg.sender);
        if (support) p.yesVoters.push(msg.sender);
        else p.noVoters.push(msg.sender);
        voteOf[id][msg.sender] = support ? 1 : 2;
        emit VoteCast(id, msg.sender, support);
        return _tally(id);
    }

    /// Only votes from *currently active* validators count.
    function _count(Proposal storage p) private view returns (uint256 yes, uint256 no) {
        for (uint256 i = 0; i < p.yesVoters.length; i++) if (isValidator[p.yesVoters[i]]) yes++;
        for (uint256 i = 0; i < p.noVoters.length; i++) if (isValidator[p.noVoters[i]]) no++;
    }

    function _tally(uint256 id) private returns (Status) {
        Proposal storage p = proposals[id];
        uint256 n = validators.length;
        uint256 need = requiredVotes();
        (uint256 yes, uint256 no) = _count(p);
        if (yes >= need) _apply(id);
        else if (n - no < need) _close(id, Status.Rejected);
        return p.status;
    }

    function _apply(uint256 id) private {
        Proposal storage p = proposals[id];
        address s = p.subject;
        if (p.kind == Kind.Add) {
            if (isValidator[s] || validators.length >= maxValidators) {
                _close(id, Status.Failed);
                return;
            }
            isValidator[s] = true;
            validators.push(s);
            emit ValidatorAdded(s, block.number);
        } else {
            if (!isValidator[s] || validators.length <= minValidators) {
                _close(id, Status.Failed);
                return;
            }
            isValidator[s] = false;
            _removeFrom(validators, s);
            emit ValidatorRemoved(s, block.number);
        }
        _close(id, Status.Executed);
    }

    function _close(uint256 id, Status status) private {
        Proposal storage p = proposals[id];
        p.status = status;
        delete openProposal[keccak256(abi.encode(p.kind, p.subject))];
        emit ProposalClosed(id, status);
    }

    /// swap-and-pop
    function _removeFrom(address[] storage arr, address a) private {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == a) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                return;
            }
        }
    }
}
