// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
package harvey.tests;

import harvey.HarveyIO;
import harvey.HarveyCmds;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HarveyIOTests {

	public HarveyIOTests() {
	}

	@Test
	public void testEcho() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("lecho one=two");
		h.actionPerformed(null);

		assertEquals("\nlecho one=two\nECHO: one:two", h.textArea.getText());
		assertEquals("", h.textCmd.getText());

		h.textCmd.setText("lecho one=two two=something");
		h.actionPerformed(null);

		assertEquals("\nlecho one=two\nECHO: one:two\nlecho one=two two=something\nECHO: one:two two:something", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testBadCommand() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("not a command");
		h.actionPerformed(null);

		assertEquals("\nnot a command\nerror: command does not exist", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testTypes() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("testTypes one=a\\ string two=0x123 three=abcd four=true");
		h.actionPerformed(null);

		assertEquals("\ntestTypes one=a\\ string two=0x123 three=abcd four=true\nSuccess", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

}
