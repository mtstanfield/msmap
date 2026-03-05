declare const L: any;

interface Window {
  msmapApi: {
    fetchStatusApi: () => Promise<any>;
    fetchHomeApi: () => Promise<any>;
    fetchMapApi: (queryString: string) => Promise<any>;
    fetchDetailApi: (queryString: string) => Promise<any>;
  };
}
