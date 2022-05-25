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

public class RemoteHarveyCmd extends HarveyCmd {
	
	public RemoteHarveyCmd() {
	}

	public String handleResult(HarveyPlugin plugin, JSONObject j) {
		plugin.log(j.toJSONString());

		return "Success";
	}

	public String sendCmd(HarveyPlugin plugin, JSONObject j) {
		plugin.getSocket().send(j);

		return "Success";
	}
}
