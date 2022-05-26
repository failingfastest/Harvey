// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;
import harvey.EchoCmd;
import harvey.TypesTestCmd;
import harvey.HarveySocketConnectCmd;
import harvey.DebugCmd;

import java.util.function.Function;
import java.util.function.Supplier;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class HarveyCmds {

	public HarveyPlugin plugin;
	public Map<String, Supplier<HarveyCmd>> commands;
	public Map<Character, Character> controlChars;

	public HarveyCmds(HarveyPlugin _plugin) {
		plugin = _plugin;
		commands = new HashMap<String, Supplier<HarveyCmd>>();
		commands.put(new EchoCmd().getCmdName(), EchoCmd::create);
		commands.put(new RemoteEchoCmd().getCmdName(), RemoteEchoCmd::create);
		commands.put(new TypesTestCmd().getCmdName(), TypesTestCmd::create);
		commands.put(new HarveySocketConnectCmd().getCmdName(), HarveySocketConnectCmd::create);
		commands.put(new DebugCmd().getCmdName(), DebugCmd::create);

		controlChars = new HashMap<Character, Character>();

		controlChars.put('r', '\r');
		controlChars.put('n', '\n');
		controlChars.put('0', '\0');
		controlChars.put('n', '\n');
		controlChars.put('f', '\f');
	}

	public String doCommand(String line) {
		String cmd = "";
		Map<String, String> args = new HashMap<String, String>();

		int i_char = 0;
		int i_arg = 0;

		for (i_char = 0; i_char < line.length(); i_char++) {
			if (line.charAt(i_char) != ' ') {
				cmd += line.charAt(i_char);
			} else {
				break;
			}
		}
		while (line.charAt(i_char) == ' ') { i_char++; }
		if (i_char >= line.length()) {
			return "error: no command provided";
		}

		Supplier<HarveyCmd> supplier = commands.get(cmd);
		if (supplier == null) {
			return "error: command does not exist";
		}
		HarveyCmd cmdObj = supplier.get();
		for (; i_char < line.length(); i_char++) {
			String arg = "";
			List<String> parts = new ArrayList<String>();
			int i_equals = 0;
			boolean haveSlash = false;

			for (i_arg = 0; i_arg + i_char < line.length(); i_arg++) {
				char c = line.charAt(i_char + i_arg);
				if (haveSlash) {
					haveSlash = false;
					if (i_char + i_arg >= line.length()) {
						break;
					}
					i_arg++;
					c = line.charAt(i_char + i_arg);
					if (controlChars.containsKey(c)) {
						c = controlChars.get(c);
					}
				} else if (c == '\\') {
					haveSlash = true;
				} else if (c == ' ') {
					while (line.charAt(i_char) == ' ') { i_char++; }
					args.put(arg.substring(0, i_equals), arg.substring(i_equals + 1));
					
					arg = "";
					break;
				} 

				if (c == '=' && i_equals == 0) {
					i_equals = i_arg;
				}

				if (!haveSlash) {
					arg += c;
				}
			}

			if (i_char + i_arg >= line.length()) {
				args.put(arg.substring(0, i_equals), arg.substring(i_equals + 1));
			}

			i_char += i_arg;
		}

		return cmdObj.apply(plugin, args);
	}
}

