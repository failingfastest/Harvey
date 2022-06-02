// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;

import java.io.IOException;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class HarveySocketConnectCmd extends HarveyCmd {

	public HarveySocketConnectCmd() {
		params.put("host", "string");
		params.put("port", "int");
		defaults.put("host", "127.0.0.1");
		defaults.put("port", "12345");
	}

	static public HarveySocketConnectCmd create() {
		return new HarveySocketConnectCmd();
	}

	public String getCmdName() {
		return "connect";
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		String host = args.get("host");
		int port = Integer.parseInt(args.get("port"));

		try {
			plugin.provider.harveyIo.harveySocket.openSocket(host, port);
		} catch (IOException ioe) {
			return "error: " + ioe.toString();
		}
		return "Success";
	}
}
