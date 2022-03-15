package no.cantara.stingray.httpclient;

import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Response;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

class DefaultStingrayHttpResponse implements StingrayHttpResponse {

    private final String requestUrl;
    private final Map<String, StingrayHttpHeader> requestHeaders;
    private final HttpEntity requestEntity;
    private final Response response;
    private final HttpResponse httpResponse;

    DefaultStingrayHttpResponse(String requestUrl, Map<String, StingrayHttpHeader> requestHeaders, HttpEntity requestEntity, Response response) {
        this.requestUrl = requestUrl;
        this.requestHeaders = requestHeaders;
        this.requestEntity = requestEntity;
        this.response = response;
        try {
            this.httpResponse = response.returnResponse();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public StingrayHttpResponse isSuccessful() throws StingrayHttpClientException {
        int statusCode = httpResponse.getStatusLine().getStatusCode();
        if (statusCode < 200 || 300 <= statusCode) {
            throw StingrayHttpClientException.builder()
                    .withUrl(requestUrl)
                    .withRequestHeaders(requestHeaders)
                    .withRequestBody(requestEntity)
                    .withStatusCode(statusCode)
                    .build();
        }
        return this;
    }

    @Override
    public StingrayHttpResponse hasStatusCode(int status) throws StingrayHttpClientException {
        int statusCode = httpResponse.getStatusLine().getStatusCode();
        if (statusCode != status) {
            throw StingrayHttpClientException.builder()
                    .withUrl(requestUrl)
                    .withRequestHeaders(requestHeaders)
                    .withRequestBody(requestEntity)
                    .withStatusCode(statusCode)
                    .build();
        }
        return this;
    }

    @Override
    public int status() {
        return httpResponse.getStatusLine().getStatusCode();
    }

    @Override
    public String statusReasonPhrase() {
        return httpResponse.getStatusLine().getReasonPhrase();
    }

    @Override
    public String protocolVersion() {
        return httpResponse.getStatusLine().getProtocolVersion().toString();
    }

    @Override
    public String firstHeader(String name) {
        return ofNullable(httpResponse.getFirstHeader(name)).map(Header::getValue).orElse(null);
    }

    @Override
    public List<String> header(String name) {
        return Arrays.stream(httpResponse.getHeaders(name))
                .map(NameValuePair::getValue)
                .collect(Collectors.toList());
    }

    @Override
    public List<String> headerNames() {
        List<String> headerNames = new ArrayList<>();
        HeaderIterator it = httpResponse.headerIterator();
        while (it.hasNext()) {
            Header header = it.nextHeader();
            headerNames.add(header.getName());
        }
        return headerNames;
    }

    @Override
    public String contentAsString() {
        HttpEntity entity = httpResponse.getEntity();
        if (entity == null) {
            return null;
        }
        try {
            return EntityUtils.toString(entity, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw StingrayHttpClientException.builder()
                    .withUrl(requestUrl)
                    .withRequestHeaders(requestHeaders)
                    .withRequestBody(requestEntity)
                    .withStatusCode(status())
                    .withResponseHeaders(headerNames().stream().collect(Collectors.toMap(k -> k, k -> toStingrayHeaders(k, httpResponse.getHeaders(k)))))
                    .build();
        }
    }

    StingrayHttpHeader toStingrayHeaders(String name, Header[] header) {
        return new DefaultStingrayHttpHeader(name, Arrays.stream(header).map(NameValuePair::getValue).collect(Collectors.toList()));
    }

    @Override
    public InputStream content() {
        try {
            HttpEntity entity = httpResponse.getEntity();
            if (entity == null) {
                return null;
            }
            return entity.getContent();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Tells the length of the content, if known.
     *
     * @return the number of bytes of the content, or
     * a negative number if unknown. If the content length is known
     * but exceeds {@link Long#MAX_VALUE Long.MAX_VALUE},
     * a negative number is returned.
     */
    @Override
    public long contentLength() {
        HttpEntity entity = httpResponse.getEntity();
        if (entity == null) {
            return 0;
        }
        return entity.getContentLength();
    }

    /**
     * Obtains the Content-Type header, if known.
     * This is the header that should be used when sending the entity,
     * or the one that was received with the entity. It can include a
     * charset attribute.
     *
     * @return the Content-Type header for this entity, or
     * {@code null} if the content type is unknown
     */
    @Override
    public String contentType() {
        HttpEntity entity = httpResponse.getEntity();
        if (entity == null) {
            return null;
        }
        return entity.getContentType().getValue();
    }

    /**
     * Obtains the Content-Encoding header, if known.
     * This is the header that should be used when sending the entity,
     * or the one that was received with the entity.
     * Wrapping entities that modify the content encoding should
     * adjust this header accordingly.
     *
     * @return the Content-Encoding header for this entity, or
     * {@code null} if the content encoding is unknown
     */
    @Override
    public String contentEncoding() {
        HttpEntity entity = httpResponse.getEntity();
        if (entity == null) {
            return null;
        }
        return entity.getContentEncoding().getValue();
    }
}