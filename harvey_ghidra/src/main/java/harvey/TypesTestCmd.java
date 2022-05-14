package harvey;

import harvey.HarveyPlugin;
import harvey.HarveyCmd;

import java.util.function.Function;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class TypesTestCmd extends HarveyCmd {
	public TypesTestCmd() {
		params.put("one", "string");
		params.put("two", "int");
		params.put("three", "hexBytes");
		params.put("four", "bool");
	}

	String applyImpl(HarveyPlugin plugin, Map<String, String> args) {
		return "Success";
	}
}
