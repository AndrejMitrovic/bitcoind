// Copyright (c) 2009 Satoshi Nakamoto
// Copyright (c) 2018 Cvsae
// Distributed under the MIT/X11 software license, see the accompanying
// file license http://www.opensource.org/licenses/mit-license.php.

import std.stdio;
import std.format;
import std.conv : to;
import std.digest.sha;
import std.digest;
import std.algorithm;
import std.range;
import std.bigint;
import std.bitmanip;
import std.uni;
import core.stdc.stdint;

import uint256;
import utils;

const uint64_t COIN = 100000000;

string CompactSize(int x)
{
    if (x < 253)
    {
       return format("%c", to!char(x));
    }

    return "";
}

class COutPoint
{
public:
    Uint256 hash = new Uint256();
    int n;

    this()
    {
        SetNull();
    }

    this(Uint256 hashIn, uint nIn)
    {
        this.hash = hashIn;
        n = nIn;
    }

    bool IsNull() const
    {
        return (this.hash == new Uint256(0) && n == -1);
    }

    void SetNull()
    {
        this.hash = 0;
        n = -1;
    }

    bool opEquals(const COutPoint a, const COutPoint b) const
    {
        return a.hash == b.hash && a.n == b.n;
    }

    string ToString() const
    {
        return format("COutPoint(%s, %d)", this.hash.ToString(), n);
    }

    void print() const
    {
        writeln(ToString());
    }
}

/// An input of a transaction.  It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
class CTxIn
{
public:
    COutPoint prevout;
    string scriptSig;
    uint nSequence;

    this()
    {
        this.nSequence = uint.max;
    }

    this(Uint256 hashPrevTx, string scriptSigIn, uint nOut,
        uint nSequenceIn = uint.max)
    {
        this.prevout = new COutPoint(hashPrevTx, nOut);
        this.scriptSig = scriptSigIn;
        this.nSequence = nSequenceIn;
    }

    this(COutPoint prevoutIn, string scriptSigIn, uint nSequenceIn = uint.max)
    {
        this.prevout = prevoutIn;
        this.scriptSig = scriptSigIn;
        this.nSequence = nSequenceIn;
    }

    bool IsFinal() const
    {
        return (this.nSequence == uint.max);
    }

    string Serialize() const
    {
        byte[] header;
        header ~= this.prevout.hash.ToString().decodeHex();
        header ~= "FFFFFFFF".decodeHex;
        header ~= CompactSize(cast(int)(this.scriptSig.length));
        header ~= this.scriptSig;
        header ~= "FFFFFFFF".decodeHex;

        return toLower((cast(ubyte[])header).toHexString);
    }

    bool opEquals(const CTxIn a, const CTxIn b) const
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    string ToString() const
    {
        string str;
        str ~= ("CTxIn(");
        str ~= this.prevout.ToString();

        if (this.prevout.IsNull())
            str ~= format(", coinbase %s", "");
        else
            str ~= format(", scriptSig=%s", this.scriptSig.encodeHex);

        if (this.nSequence != uint.max)
            str ~= format(", nSequence=%u", this.nSequence);

        str ~= ")";

        return str;
    }

    void print() const
    {
        writeln(ToString());
    }
}

/// An output of a transaction.  It contains the public key that the next input
/// must be able to sign with to claim it.
class CTxOut
{
public:
    uint64_t nValue;
    string scriptPubKey;

    this()
    {
        SetNull();
    }

    this(uint64_t nValueIn, string scriptPubKeyIn)
    {
        this.nValue = nValueIn;
        this.scriptPubKey = scriptPubKeyIn;
    }

    void SetNull()
    {
        this.nValue = -1;
        this.scriptPubKey = "0";
    }

    bool IsNull()
    {
        return (this.nValue == -1);
    }


    bool opEquals(const CTxOut a, const CTxOut b) const
    {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    string ToString() const
    {
        return format("CTxOut(nValue=%d.%08d, scriptPubKey=%s)",
            this.nValue / COIN, this.nValue % COIN, this.scriptPubKey);
    }

    string Serialize() const
    {
        byte[] header;
        header ~= nativeToLittleEndian!ulong(this.nValue);
        header ~= CompactSize(cast(char)(this.scriptPubKey.length / 2));
        header ~= this.scriptPubKey.decodeHex;
        return toLower((cast(ubyte[]) header).toHexString);
    }

    void print() const
    {
        writeln(ToString());
    }
}

/// The basic transaction that is broadcasted on the network and contained in
/// blocks.  A transaction can contain multiple inputs and outputs.
class CTransaction
{
public:
    int nVersion;
    CTxIn[] vin;
    CTxOut[] vout;
    int nLockTime;

    this()
    {
        SetNull();
    }

    void SetNull()
    {
        this.nVersion = 1;
        this.vin  ~= new CTxIn;
        this.vout ~= new CTxOut;
        this.nLockTime = 0;
    }

    bool IsFinal() const
    {
        if (this.nLockTime == 0 || this.nLockTime < 7)
        {
            return true;
        }

        foreach(const CTxIn txin; this.vin)
        {
            if(!txin.IsFinal())
            {
                return false;
            }
        }

        return true;
    }

    string Serialize() const
    {
        byte[] header;
        // version
        header ~= nativeToLittleEndian(this.nVersion);

        // number of transaction inputs
        header ~= CompactSize(to!int(this.vin.length));

        // transactions inputs
        for( int i = 0; i < this.vin.length; ++i )
        {
            foreach(const txin; this.vin)
            {
                header ~= this.vin[i].Serialize().decodeHex();
            }
        }

        // number of transaction outputs
        header ~= CompactSize(to!int(this.vout.length));

        // transactions outputs
        for (int i = 0; i < this.vout.length; ++i)
        {
            foreach(const txout; this.vout)
            {
                header ~= this.vout[i].Serialize().decodeHex();
            }
        }

        // locktime
        header ~= nativeToLittleEndian(this.nLockTime);

        return toLower((cast(ubyte[]) header).toHexString);
    }

    bool opEquals(const CTransaction a, const CTransaction b) const
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    Uint256 GetHash() const
    {
        auto sha256 = new SHA256Digest();

        return new Uint256(
            toLower(
                to!string(
                    toHexString(
                        sha256.digest(
                            sha256.digest(Serialize.decodeHex)))
                        .chunks(2).array.retro.joiner)));

    }

    bool IsCoinBase() const
    {
        return (this.vin.length == 1 && this.vin[0].prevout.IsNull());
    }

    int64_t GetValueOut() const
    {
        int64_t nValueOut = 0;
        foreach(const CTxOut txout; this.vout)
        {
            if (txout.nValue < 0)
            {
                throw new Exception("CTransaction::GetValueOut() : negative value");
            }

            nValueOut += txout.nValue;
        }

        return nValueOut;
    }

    bool CheckTransaction() const
    {
        // Basic checks that don't depend on any context
        if (this.vin.length == 0 || this.vout.length == 0)
        {
            throw new Exception("CTransaction::CheckTransaction() : vin or vout empty");
        }

        // Check for negative values
        foreach(const CTxOut txout; this.vout)
        {
            if (txout.nValue < 0)
            {
                throw new Exception("CTransaction::CheckTransaction() : txout.nValue negative");
            }
        }

        if (IsCoinBase())
        {
            if (this.vin[0].scriptSig.length < 2 || this.vin[0].scriptSig.length > 100)
                throw new Exception("CTransaction::CheckTransaction() : coinbase script size");
        }
        else
        {
            foreach(const CTxIn txin; this.vin)
            {
                if (txin.prevout.IsNull())
                    throw new Exception("CTransaction::CheckTransaction() : prevout is null");
            }
        }

        return true;
    }

    string ToString() const
    {
        string str;
        str ~= format("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, nLockTime=%d)\n",
            GetHash().ToString(), this.nVersion, this.vin.length, this.vout.length, this.nLockTime);

        for (int i = 0; i < this.vin.length; i++)
            str ~= format(" %s \n", this.vin[i].ToString());

        for (int i = 0; i < this.vout.length; i++)
            str ~= format(" %s \n", this.vout[i].ToString());

        return str;
    }

    void print() const
    {
        writeln(ToString());
    }
}

/// Nodes collect new transactions into a block, hash them into a hash tree,
/// and scan through nonce values to make the block's hash satisfy proof-of-work
/// requirements.  When they solve the proof-of-work, they broadcast the block
/// to everyone and the block is added to the block chain.  The first transaction
/// in the block is a special one that creates a new coin owned by the creator
/// of the block.
///
/// Blocks are appended to blk0001.dat files on disk.  Their location on disk
/// is indexed by CBlockIndex objects in memory.
class CBlock
{
public:
    // block header
    uint32_t nVersion;
    Uint256 hashPrevBlock = new Uint256();
    Uint256 hashMerkleRoot = new Uint256();
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    CTransaction[] vtx;

    this()
    {
        SetNull();
    }

    void SetNull()
    {
        this.nVersion = 1;
        this.hashPrevBlock = 0;
        this.hashMerkleRoot = 0;
        this.nTime = 0;
        this.nBits = 0;
        this.nNonce = 0;
        //this.vtx.clear();
        //this.vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (this.nBits == 0);
    }

    string Serialize() const
    {
        // block header serialization
        byte[] header;

        header ~= nativeToLittleEndian(this.nVersion);
        header ~= to!string(this.hashPrevBlock.ToString().chunks(2).array.retro.joiner).decodeHex;
        header ~= to!string(this.hashMerkleRoot.ToString().chunks(2).array.retro.joiner).decodeHex;
        header ~= nativeToLittleEndian(this.nTime);
        header ~= nativeToLittleEndian(this.nBits);
        header ~= nativeToLittleEndian(this.nNonce);

        return toLower((cast(ubyte[]) header).toHexString);
    }

    void Deserialize(string block)
    {
        this.nVersion = littleEndianToNative!int(cast(ubyte[4])block.decodeHex()[0..4]);
        this.hashPrevBlock = new Uint256(to!string(block[8..72].chunks(2).array.retro.joiner));
        this.hashMerkleRoot = new Uint256(to!string(block[72..136].chunks(2).array.retro.joiner));
        this.nTime = littleEndianToNative!int(cast(ubyte[4])block.decodeHex()[68..72]);
        this.nBits = littleEndianToNative!int(cast(ubyte[4])block.decodeHex()[72..76]);
        this.nNonce = littleEndianToNative!int(cast(ubyte[4])block.decodeHex()[76..80]);
    }

    string DumpAll()
    {
        byte[] header;

        header ~= nativeToLittleEndian(this.nVersion);
        header ~= to!string(this.hashPrevBlock.ToString().chunks(2).array.retro.joiner).decodeHex;
        header ~= to!string(this.hashMerkleRoot.ToString().chunks(2).array.retro.joiner).decodeHex;
        header ~= nativeToLittleEndian(this.nTime);
        header ~= nativeToLittleEndian(this.nBits);
        header ~= nativeToLittleEndian(this.nNonce);

        header ~= CompactSize(to!int(this.vtx.length));

        foreach (const CTransaction tx; this.vtx)
            header ~= tx.Serialize().decodeHex;

        return toLower((cast(ubyte[]) header).toHexString);
    }

    Uint256 GetHash() const
    {
        auto sha256 = new SHA256Digest();

        return new Uint256(
            toLower(
                to!string(
                    toHexString(sha256.digest(sha256.digest(Serialize.decodeHex)))
            .chunks(2).array.retro.joiner)));
    }

    Uint256 BuildMerkleTree() const
    {
        Uint256[] txhashes;

        foreach (const CTransaction tx; this.vtx)
        {
            // calculate transactions hashes and add them to an array
            txhashes ~= new Uint256(tx.GetHash());
        }

        if (txhashes.length == 1)
        {
            // case block have only a coinbase tx
            // merkle root is the coinbase transaction hash
            return txhashes[0];
        }

        if (txhashes.length > 1)
        {
            // drey todo: where is this part??

            // case we have a regualr tx
            // calculate merkle root
        }

        return new Uint256(0);
    }

    bool CheckBlock() const
    {
        // These are checks that are independent of context
        // that can be verified before saving an orphan block.

        // Size limits
        if (this.vtx.length == 0 || this.vtx.length > 100_000_000)
        {
            throw new Exception("CheckBlock() : size limits failed");
        }

        // Check timestamp
        if (this.nTime > GetAdjustedTime() + 2 * 60 * 60)
        {
            throw new Exception("CheckBlock() : block timestamp too far in the future");
        }

        // First transaction must be coinbase, the rest must not be
        if (this.vtx.length == 0 || !this.vtx[0].IsCoinBase())
        {
            throw new Exception("CheckBlock() : first tx is not coinbase");
        }

        for (int i = 1; i < this.vtx.length; i++)
        {
            if (this.vtx[i].IsCoinBase())
            {
                throw new Exception("CheckBlock() : more than one coinbase");
            }
        }

        // Check transactions
        foreach(const CTransaction tx; this.vtx)
        {
            if (!tx.CheckTransaction())
            {
                throw new Exception("CheckBlock() : CheckTransaction failed");
            }
        }

        // Check merkleroot
        if (this.hashMerkleRoot != BuildMerkleTree())
        {
            throw new Exception("CheckBlock() : hashMerkleRoot mismatch");
        }

        return true;
    }

    void print() const
    {
        writeln(format("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
            GetHash().ToString(), this.nVersion, this.hashPrevBlock.ToString(), this.hashMerkleRoot.ToString(), this.nTime, this.nBits, this.nNonce));

        for (int i = 0; i < this.vtx.length; i++)
        {
            writeln("  ");
            this.vtx[i].print();
        }
    }
}

bool ProcessBlock(CBlock pblock)
{
    Uint256 hash = pblock.GetHash();

    // Check for duplicate
    // stable
    // orphan

    // Preliminary checks
    if (!pblock.CheckBlock())
    {
        throw new Exception("ProcessBlock() : CheckBlock FAILED");
    }

    writeln("ProcessBlock: ACCEPTED\n");

    return true;
}
