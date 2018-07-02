package burp;

/*
 * @(#)IExtensionStateListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerExtensionStateListener()</code> to
 * register an extension state listener. The listener will be notified of
 * changes to the extension's state. <b>Note:</b> Any extensions that start
 * background threads or open system resources (such as files or database
 * connections) should register a listener and terminate threads / close
 * resources when the extension is unloaded.
 * ----------------------------------------------------------------------
 * 扩展可以实现这个接口，然后调用
 * IBurpExtenderCallbacks.registerExtensionStateListener()
 * 来注册扩展状态监听器。 监听器将被通知改变扩展的状态。 
 * 注意：
 * 任何开启后台线程或开放的系统资源（如文件或数据库连接）的扩展都应该注册一个监听器
 * 当扩展名卸载时终止线程/关闭资源。
 */
public interface IExtensionStateListener
{
    /**
     * This method is called when the extension is unloaded.
     */
    void extensionUnloaded();
}
