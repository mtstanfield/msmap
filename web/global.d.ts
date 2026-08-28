declare const L: any;
declare const protomapsL: {
    leafletLayer(options: Record<string, unknown>): { addTo(map: unknown): unknown };
};

interface Window {
  msmapDeps: any;
  msmapApi: {
    fetchStatusApi: () => Promise<any>;
    fetchHomeApi: () => Promise<any>;
    fetchMapApi: (queryString: string) => Promise<any>;
    fetchDetailApi: (queryString: string) => Promise<any>;
  };
}
