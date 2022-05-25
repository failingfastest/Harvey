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

public class EchoCmd extends HarveyCmd {
	public EchoCmd() {
		params.put("one", "string");
		params.put("two", "string");
	}

	static public EchoCmd create() {
		return new EchoCmd();
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		String output = "ECHO: ";
		int index = 0;
		for (var o : args.entrySet()) {
			output = output + o.getKey() + ":" + o.getValue();
			if (index < args.size() - 1) {
				output = output + " ";
			}
			index++;
		}
		return output;
	}
}
