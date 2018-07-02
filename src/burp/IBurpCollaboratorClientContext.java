package burp;

/*
 * @(#)IBurpCollaboratorClientContext.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface represents an instance of a Burp Collaborator client context,
 * which can be used to generate Burp Collaborator payloads and poll the
 * Collaborator server for any network interactions that result from using those
 * payloads. Extensions can obtain new instances of this class by calling
 * <code>IBurpExtenderCallbacks.createBurpCollaboratorClientContext()</code>.
 * Note that each Burp Collaborator client context is tied to the Collaborator
 * server configuration that was in place at the time the context was created.
 * ---------------------------------------------------------------------------
 * 此接口表示Burp Collaborator客户端上下文的一个实例
 * 可用于生成Burp Collaborator有效载荷并轮询协作者服务器，用于任何由使用它们导致的网络交互有效载荷
 * 扩展可以通过调用获取此类的新实例 IBurpExtenderCallbacks.createBurpCollaboratorClientContext()
 * 请注意，每个Burp Collaborator客户端上下文都与Collaborator绑定，服务器配置在创建上下文时就位
 */
public interface IBurpCollaboratorClientContext
{

    /**
     * This method is used to generate new Burp Collaborator payloads.
     *
     * @param includeCollaboratorServerLocation Specifies whether to include the
     * Collaborator server location in the generated payload.
     * @return The payload that was generated.
     */
    String generatePayload(boolean includeCollaboratorServerLocation);

    /**
     * This method is used to retrieve all interactions received by the
     * Collaborator server resulting from payloads that were generated for this
     * context.
     *
     * @return The Collaborator interactions that have occurred resulting from
     * payloads that were generated for this context.
     */
    List<IBurpCollaboratorInteraction> fetchAllCollaboratorInteractions();

    /**
     * This method is used to retrieve interactions received by the Collaborator
     * server resulting from a single payload that was generated for this
     * context.
     *
     * @param payload The payload for which interactions will be retrieved.
     * @return The Collaborator interactions that have occurred resulting from
     * the given payload.
     */
    List<IBurpCollaboratorInteraction> fetchCollaboratorInteractionsFor(String payload);

    /**
     * This method is used to retrieve all interactions made by Burp Infiltrator
     * instrumentation resulting from payloads that were generated for this
     * context.
     *
     * @return The interactions triggered by the Burp Infiltrator
     * instrumentation that have occurred resulting from payloads that were
     * generated for this context.
     */
    List<IBurpCollaboratorInteraction> fetchAllInfiltratorInteractions();

    /**
     * This method is used to retrieve interactions made by Burp Infiltrator
     * instrumentation resulting from a single payload that was generated for
     * this context.
     *
     * @param payload The payload for which interactions will be retrieved.
     * @return The interactions triggered by the Burp Infiltrator
     * instrumentation that have occurred resulting from the given payload.
     */
    List<IBurpCollaboratorInteraction> fetchInfiltratorInteractionsFor(String payload);

    /**
     * This method is used to retrieve the network location of the Collaborator
     * server.
     *
     * @return The hostname or IP address of the Collaborator server.
     */
    String getCollaboratorServerLocation();
}
