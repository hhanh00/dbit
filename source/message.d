import std.bitmanip;
import std.digest.sha;
import std.outbuffer;
import std.conv;
import std.random;
import std.datetime;
import std.socket;

class Message {
	abstract @property string command();

	abstract ubyte[] serialize();
	static uint calc_checksum(ubyte[] payload) {
		SHA256 sha;
		sha.start();
		sha.put(payload);
		auto sha_1 = sha.finish();
		sha.start();
		sha.put(sha_1);
		auto sha_2 = assumeUnique(sha.finish());
		return sha_2.read!(uint, Endian.littleEndian)();
	}
}

class Version : Message {
	uint vers;
	ulong services;
	ulong timestamp;
	Internet6Address recv;
	Internet6Address from;
	ulong nonce;
	string user_agent;
	uint height;

	override @property string command() { return "version"; }
	this(uint vers_, ulong services_, ulong timestamp_, Internet6Address recv_, Internet6Address from_,
		ulong nonce_, string user_agent_, uint height_) {
		vers = vers_;
		services = services_;
		timestamp = timestamp_;
		recv = recv_;
		from = from_;
		nonce = nonce_;
		user_agent = user_agent_;
		height = height_;
	}

	this(Internet6Address remote, uint height) {
		auto local = new Internet6Address(Internet6Address.ADDR_ANY, Internet6Address.PORT_ANY);
		auto nonce = uniform!uint();
		auto now = Clock.currTime.toUnixTime;
		this(0x70001, 1, now, remote, local, nonce, "/D-Bit/", height);
	}

	override ubyte[] serialize() {
		auto bb = new OutBuffer;
		bb.put(vers);
		bb.put(services);
		bb.put(timestamp);
		put_ipv6(bb, recv);
		put_ipv6(bb, from);
		bb.put(nonce);
		put_varstring(bb, user_agent);
		bb.put(height);

		return bb.toBytes;
	}

	void put_ipv6(OutBuffer bb, Internet6Address addr) {
		bb.put(services);
		bb.put(addr.addr());
		bb.put(addr.port());
	}

	void put_varstring(OutBuffer bb, string s) {
		put_varint(bb, s.length);
		bb.put(s);
	}

	void put_varint(OutBuffer bb, size_t i) {
		if (i <= 0xFC) 
			bb.put(to!ubyte(i));
		else if (i <= 0xFFFF) {
			bb.put('\xFD');
			bb.put(to!ushort(i));
		}
		else if (i <= 0xFFFFFFFF) {
			bb.put('\xFE');
			bb.put(to!uint(i));
		}
		else {
			bb.put('\xFF');
			bb.put(i);
		}
	}
}

class Verack : Message {
	override @property string command() { return "verack"; }
	override ubyte[] serialize() {
		ubyte[] empty;
		return empty;
	}
}
