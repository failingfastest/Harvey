
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

		h.textCmd.setText("echo one=two");
		h.actionPerformed(null);

		assertEquals("\nECHO: one:two", h.textArea.getText());
		assertEquals("", h.textCmd.getText());

		h.textCmd.setText("echo one=two two=something");
		h.actionPerformed(null);

		assertEquals("\nECHO: one:two\nECHO: one:two two:something", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testBadCommand() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("not a command");
		h.actionPerformed(null);

		assertEquals("\nerror: command does not exist", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

	@Test
	public void testTypes() {
		HarveyCmds c = new HarveyCmds(null);
		HarveyIO h = new HarveyIO(null, c);

		h.textCmd.setText("testTypes one=a\\ string two=0x123 three=abcd four=true");
		h.actionPerformed(null);

		assertEquals("\nSuccess", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}

}
