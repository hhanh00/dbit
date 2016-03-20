import std.stdio;
import std.socket;
import std.algorithm;
import std.conv;
import std.outbuffer;
import std.bitmanip;

import libasync;

import message;

class Peer {
	EventLoop ev_loop;
	PeerManager pm;
	NetworkAddress peer_addr;
	AsyncTCPConnection tcp_connection;

	this(EventLoop ev_loop_, PeerManager pm_, NetworkAddress peer_addr_) {
		ev_loop = ev_loop_;
		pm = pm_;
		peer_addr = peer_addr_;
	}

	void connect() {
		writefln("Attempting connection to %s", peer_addr);
		tcp_connection = new AsyncTCPConnection(ev_loop);
		tcp_connection.peer(peer_addr);
		tcp_connection.run(&handler);
	}

	void handler(TCPEvent event) {
		switch (event) {
			case TCPEvent.CONNECT:
				writefln("Connected to %s", peer_addr);
				on_connected();
			break;

			case TCPEvent.ERROR:
				writefln("Error %s %s", tcp_connection.error(), peer_addr);

				pm.remove_peer(this);
				break;

			default: break;
		}
	}

	void on_connected() {
		handshake();
	}

	void handshake() {
		send_version();
		wait_for_version_and_verack();
		send_verack();
	}

	void send_version() {
		ubyte[16] ipv6_addr_bytes;
		ipv6_addr_bytes[10] = 0xFF;
		ipv6_addr_bytes[11] = 0xFF;
		auto p = ipv6_addr_bytes[];
		auto addr_v4 = peer_addr.sockAddrInet4.sin_addr.s_addr;
		p.write!(uint, Endian.littleEndian)(addr_v4, 12);
		auto ipv6_addr = new Internet6Address(ipv6_addr_bytes, peer_addr.port);

		auto vers = new Version(ipv6_addr, 0);
		send_message(vers);
	}

	void send_verack() {
		auto verack = new Verack;
		send_message(verack);
	}

	void send_message(Message m) {
		auto out_buffer = new OutBuffer;
		out_buffer.append!(uint, Endian.littleEndian)(0xD9B4BEF9);
		char[12] command_bytes;
		auto command = m.command;
		command_bytes[0..command.length] = command;
		out_buffer.append!(uint, Endian.littleEndian)(0xD9B4BEF9);
		out_buffer.put(command_bytes);
		auto payload = m.serialize();
		out_buffer.append!(uint, Endian.littleEndian)(payload.length);
		auto checksum = Message.calc_checksum(payload);
		out_buffer.append!(uint, Endian.littleEndian)(checksum);
		out_buffer.put(payload);
		auto bb = out_buffer.toBytes;
		tcp_connection.send(bb);
	}

	void wait_for_version_and_verack() {}
}

class PeerManager {
	const int max_peers = 5;

	EventLoop ev_loop;
	shared AsyncDNS dns;
	NetworkAddress[] peer_pool;
	Peer[] peers;

	this(EventLoop ev_loop_) {
		ev_loop = ev_loop_;
		dns = new shared AsyncDNS(ev_loop);
		dns.handler(&dns_handler);
	}

	void init_from_seed() {
		dns.resolveHost("seed.bitnodes.io");
	}

	void dns_handler(NetworkAddress seed_addr) {
		seed_addr.port(8333);
		peer_pool ~= seed_addr;
	}

	void print_peer_pool() {
		foreach (addr; peer_pool) {
			writefln("Seed %s", addr);
		}
	}

	void try_connect() {
		auto n_peers = peers.length;
		writefln("try_connect %d", n_peers);
		if (n_peers < max_peers) {
			foreach (i; n_peers..max_peers) {
				if (peer_pool.empty)
					break;

				auto peer_addr = peer_pool.front();
				peer_pool.popFront();
				auto peer = new Peer(ev_loop, this, peer_addr);
				peers ~= peer;
				peer.connect();
			}
		}
	}

	void remove_peer(Peer peer) {
		writefln("Removing peer %s", peer.peer_addr);
		auto index = peers.countUntil(peer);
		writeln(index);
		if (index >= 0) {
			peers = peers.remove(index);
			try_connect();
		}
	}
}

void main()
{
	auto ev_loop = new EventLoop;
	auto pm = new PeerManager(ev_loop);
	pm.init_from_seed();

	pm.print_peer_pool();
	pm.try_connect();

	while (true) {
		ev_loop.loop();
	}
}
