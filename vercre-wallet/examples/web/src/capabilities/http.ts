import * as st from 'shared_types/types/shared_types';

export const request = async ({
    url,
    method,
    headers,
}: st.HttpRequest): Promise<st.HttpResponse> => {
    const request = new Request(url, {
        method,
        headers: headers.map((header) => [header.name, header.value]),
    });
    console.log('http', request);

    const response = await fetch(request);

    const responseHeaders: st.HttpHeader[] = Array.from(
        response.headers.entries(),
        ([name, value]) => new st.HttpHeader(name, value),
    );

    const body = await response.arrayBuffer();

    return new st.HttpResponse(
        response.status,
        responseHeaders,
        Array.from(new Uint8Array(body)),
    );
};
