// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey;

import harvey.HarveyIO;

import java.awt.BorderLayout;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import ghidra.program.model.listing.*;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "harvey",
	category = PluginCategoryNames.COMMON,
	shortDescription = "A two faced gdb bridge.",
	description = "Allows control two and fro from gdb."
)
//@formatter:on
public class HarveyPlugin extends ProgramPlugin {

	public MyProvider provider;
	public boolean debug_;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HarveyPlugin(PluginTool tool) {
		super(tool, true, true);

		debug_ = false;
		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	public void setDebug(boolean newDebug) {
		debug_ = newDebug;
	}

	public void log(String line) {
		if (provider != null && provider.harveyIo != null) {
			provider.harveyIo.log(line);
		}
	}

	public void debug(String line) {
		if (debug_) {
			log(line);
		}
	}

	public HarveySocket getSocket() {
		return provider.harveyIo.harveySocket;
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	public Program getProgram() {
		return this.currentProgram;
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	public static class MyProvider extends ComponentProvider {


		private DockingAction action;
		public HarveyIO harveyIo;
		public HarveyCmds cmds;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);

			cmds = new HarveyCmds((HarveyPlugin)plugin);
			harveyIo = new HarveyIO((HarveyPlugin)plugin, cmds);
			harveyIo.start();

			setVisible(true);
			createActions();
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), harveyIo.getPanel(), "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return harveyIo.getPanel();
		}
	}

}
