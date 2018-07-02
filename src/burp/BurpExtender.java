package burp;

import java.awt.Component;
import java.io.PrintWriter;

import javax.swing.JPanel;

/**
 * 插件入口
 * @author lynn
 */
public class BurpExtender implements IBurpExtender, ITab {
	
    private static final String name = "Singularity Security HLog v1.0 _ by lynn";
    
    public JPanel pluginTabPanel;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    	pluginTabPanel = new Tab_SimpleHttpServer();
        
        callbacks.setExtensionName(name);
        callbacks.customizeUiComponent(pluginTabPanel);
        callbacks.addSuiteTab(BurpExtender.this);
        
        new PrintWriter(callbacks.getStdout(), true).println("Loaded " + name + " successfully.");
    }

	@Override
	public String getTabCaption() {
		return "HLog";
	}

	@Override
	public Component getUiComponent() {
		return pluginTabPanel;
	}
}

