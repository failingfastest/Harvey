// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyIO;

import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.channels.spi.*;
import java.util.*;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

class HarveySocket implements Runnable {

	public HarveyPlugin plugin;
	public ByteBuffer buffer;
	public InputStreamReader reader;
	public OutputStreamWriter writer;
	public boolean keepRunning;
	public ByteBuffer input;
	public byte[] commandArray;
	public byte[] lengthArray;
	public int commandOffset;
	public int lengthOffset;
	public SelectorProvider selectorProvider;
	public Selector selector;
	public SocketChannel channel;
	public HarveyIO harveyIo;
	public int id;
	public Map<String, RemoteHarveyCmd> commands;

	public HarveySocket(HarveyPlugin plugin_, HarveyIO harveyIo_) throws IOException {
		plugin = plugin_;
		keepRunning = true;
		input = ByteBuffer.allocate(4096);
		commandArray = new byte[1 << 20];
		commandOffset = 0;
		lengthArray = new byte[8];
		lengthOffset = 0;
		selector = Selector.open();
		selectorProvider = selector.provider();
		channel = selectorProvider.openSocketChannel();
		harveyIo = harveyIo_;
		id = 1;
		commands = new HashMap<String, RemoteHarveyCmd>();
	}

	@Override
	public void run() {
		while (keepRunning) {

			if (channel == null || !channel.isConnected()) {
				plugin.debug("not connected");
				try {
					Thread.sleep(100);
				} catch (InterruptedException ie) {
				}
			} else {
				if (waitForInput()) {
					plugin.debug("receiving");
					recv();
				}
			}
		}
	}

	public boolean waitForInput() {
		boolean ret = false;
		int nReady = 0;

		try {
			channel.register(selector, SelectionKey.OP_READ);
			nReady = selector.select(100);
			if (nReady > 0) {
				Set<SelectionKey> selectedKeys = selector.selectedKeys();
				selectedKeys.clear();
				ret = true;
			}
		} catch (IOException ioe) {
			plugin.log(ioe.toString());
		}

		return ret;
	}

	public void openSocket(String host, int port) throws IOException {
		channel = selectorProvider.openSocketChannel();
		channel.connect(new InetSocketAddress(host, port));
		channel.configureBlocking(false);
		channel.register(selector, SelectionKey.OP_READ);
	}

	public void closeSocket() {
		if (channel != null) {
			try {
				channel.socket().close();
			} catch (IOException ioe) {
				plugin.log(ioe.toString());
			}
		}

		channel = null;
	}

	public void recv() {
		int readLength = 0;
		long jsonLength = 0;
		commandOffset = 0;
		lengthOffset = 0;
		boolean firstInput = true;
		int inputRemaining = 0;

		while (firstInput || inputRemaining > 0) {
			plugin.debug("input loop");
			firstInput = false;
			while (lengthOffset < 8) {
				plugin.debug("length");
				waitForInput();
				if (channel == null || !channel.isConnected()) {
					closeSocket();
					return;
				}
				if (inputRemaining == 0) {
					try {
						input.clear();
						inputRemaining = channel.read(input);
						if (inputRemaining <= 0) {
							closeSocket();
							return;
						}
						input.flip();
					} catch (IOException ioe) {
						plugin.log("hdr: " + ioe.toString());
						return;
					}
				}

				if (inputRemaining < 0) {
					
					closeSocket();
				} else if (inputRemaining >= lengthArray.length - lengthOffset) {
					plugin.debug("got all length");
					input.get(lengthArray, lengthOffset, lengthArray.length - lengthOffset);
					lengthOffset = lengthArray.length;
					inputRemaining -= lengthArray.length;
				} else {
					plugin.debug("length offset: " + Integer.toString(lengthOffset));
					input.get(lengthArray, lengthOffset, inputRemaining);
					lengthOffset += inputRemaining;
					inputRemaining = 0;
				}
			}

			jsonLength = 0;
			int shift = 0;
			for (int i = 0; i < 8; i++) {
				jsonLength += ((long)lengthArray[i]) << shift;
				shift += 8;
			}

			plugin.debug("array: " + Arrays.toString(lengthArray));
			plugin.debug("length: " + Long.toString(jsonLength));
			while (commandOffset < (int)jsonLength) {
				plugin.debug("commandOffset: " + Integer.toString(commandOffset));
				plugin.debug("remaining: " + Integer.toString(inputRemaining));
				if (inputRemaining == 0) {
					try {
						input.clear();
						waitForInput();
						inputRemaining = channel.read(input);
						if (inputRemaining <= 0) {
							closeSocket();
							return;
						}
						input.flip();
					} catch (IOException ioe) {
						plugin.log("cmd: " + ioe.toString());
						return;
					}
				}

				if (inputRemaining < 0) {
					closeSocket();
				} else if (commandOffset + inputRemaining >= (int)jsonLength ) {
					plugin.debug("got all of command");
					input.get(commandArray, commandOffset, (int)jsonLength - commandOffset);
					String jsonString = new String(commandArray, 0, (int)jsonLength);
					handleInput(jsonString);
					inputRemaining -= ((int)jsonLength - commandOffset);
					commandOffset = (int)jsonLength;
					break;
				} else if (inputRemaining > 0) {
					input.get(commandArray, commandOffset, inputRemaining);
					commandOffset += inputRemaining;
					inputRemaining = 0;
				}
			}
		}
		plugin.debug("end recv");
	}

	public void handleInput(String jsonString) {
		JSONParser parser = new JSONParser();
		JSONObject object;

		try {
			object = (JSONObject)parser.parse(jsonString);
		} catch (ParseException pe) {
			return;
		}

		String type = (String)object.get("type");
		String id = (String)object.get("id");

		if (type.equals("command")) {
			handleIncomingCommand(object, id);
		} else if (type.equals("result")) {
			handleIncomingResult(object, id);
		}
	}

	public void handleIncomingCommand(JSONObject j, String id) {
	}

	public void handleIncomingResult(JSONObject j, String id) {
		RemoteHarveyCmd cmd = commands.get(id);

		if (id == null) {
			plugin.log("could not find command " + id);
			return;
		}

		cmd.handleResult(plugin, j);
	}

	public void send(JSONObject j) {
		String jj = j.toJSONString();
		long length = (long)jj.length();

		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + (int)length);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putLong(length);
		buffer.put(jj.getBytes());
		buffer.flip();

		plugin.debug("Sending " + Integer.toString(buffer.remaining()));
		while (buffer.remaining() > 0) {
			try {
				channel.write(buffer);
			} catch (IOException ioe) {
				plugin.log(ioe.toString());
			}
		}
	}

	public JSONObject getCmdJsonObj(RemoteHarveyCmd cmd) {
		JSONObject j = new JSONObject();
		String idString = Integer.toString(id);

		j.put("type", "command");
		j.put("id", idString);
		j.put("cmd", cmd.getCmdName());
		cmd.setId(idString);
		commands.put(idString, cmd);
		id++;

		j.put("args", new JSONObject());

		return j;
	}
}

