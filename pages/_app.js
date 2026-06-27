import '../styles/globals.css';

export default function App({ Component, pageProps }) {
  // Diagnostics: prove _app.js is actually running
  if (typeof window !== 'undefined') {
    console.log('[APP] _app.js loaded');
  }

  return (
    <>
      {/* Diagnostics: prove global CSS can be injected from here too */}
      <style jsx global>{`
        body { /* comment this out later */
          /* background: #101010; */
        }
      `}</style>
      <Component {...pageProps} />
    </>
  );
}
