// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;
import harvey.GdbRawCmd;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class GdbRunCmd extends GdbRawCmd {
	public GdbRunCmd() {
		defaults.put("cmd", "continue");
	}

	static public GdbRunCmd create() {
		return new GdbRunCmd();
	}

	public String getCmdName() {
		return "gdbRun";
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		JSONObject cmd = plugin.getSocket().getCmdJsonObj(this);

		sendCmd(plugin, cmd);

		return "Sending gdb run command: " + args.get("cmd");
	}
}
