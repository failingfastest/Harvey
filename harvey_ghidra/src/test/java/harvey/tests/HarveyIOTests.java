
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

		h.textCmd.setText("echo one");
		h.actionPerformed(null);

		assertEquals("\nECHO: one", h.textArea.getText());
		assertEquals("", h.textCmd.getText());

		h.textCmd.setText("echo two");
		h.actionPerformed(null);

		assertEquals("\nECHO: one\nECHO: two", h.textArea.getText());
		assertEquals("", h.textCmd.getText());
	}
}
