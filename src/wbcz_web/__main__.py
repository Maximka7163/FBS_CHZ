import argparse,uvicorn
def main()->None:
 p=argparse.ArgumentParser(description="Run isolated WBCZ web service");p.add_argument("--host",default="127.0.0.1");p.add_argument("--port",type=int,default=8765);a=p.parse_args();uvicorn.run("wbcz_web.main:app",host=a.host,port=a.port,reload=False)
if __name__=="__main__":main()
