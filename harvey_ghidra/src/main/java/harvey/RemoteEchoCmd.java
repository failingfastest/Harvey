// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class RemoteEchoCmd extends RemoteHarveyCmd {
	public RemoteEchoCmd() {
		params.put("one", "string");
		params.put("two", "string");
	}

	static public RemoteEchoCmd create() {
		return new RemoteEchoCmd();
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		JSONObject cmd = plugin.getSocket().getCmdJsonObj(this);

		JSONObject jargs = (JSONObject)cmd.get("args");
		for (Map.Entry<String,String> entry : args.entrySet()) {
			jargs.put(entry.getKey(), entry.getValue());
		}

		sendCmd(plugin, cmd);

		return "Sending remote echo";
	}
}
