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

public class DebugCmd extends HarveyCmd {
	public DebugCmd() {
		params.put("value", "bool");
	}

	static public DebugCmd create() {
		return new DebugCmd();
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		String value = args.get("value");

		if (value.toLowerCase().equals("true")) {
			plugin.setDebug(true);
		} else {
			plugin.setDebug(false);
		}

		return "Success";
	}
}
