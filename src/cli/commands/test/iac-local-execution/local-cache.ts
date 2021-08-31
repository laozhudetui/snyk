import * as path from 'path';
import * as fs from 'fs';
import { EngineType, IaCErrorCodes } from './types';
import * as needle from 'needle';
import * as rimraf from 'rimraf';
import { createIacDir, extractBundle } from './file-utils';
import * as Debug from 'debug';
import { CustomError } from '../../../../lib/errors';
import * as analytics from '../../../../lib/analytics';
import ReadableStream = NodeJS.ReadableStream;
import { getErrorStringCode } from './error-utils';
import { Readable } from "stream"
const tar = require('tar-stream');
const streamifier = require('streamifier');

import * as config from '../../../../lib/config';
import { api } from '../../../../lib/api-token';
// import { isCI } from '../../../../lib/is-ci';
import { makeRequest } from '../../../../lib/request';
// import { Payload } from '../../../../lib/request/types';
import { FailedToGetIacOrgSettingsError } from './org-settings/get-iac-org-settings';
import * as zlib from 'zlib'

const debug = Debug('iac-local-cache');

export const LOCAL_POLICY_ENGINE_DIR = '.iac-data';

const KUBERNETES_POLICY_ENGINE_WASM_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'k8s_policy.wasm',
);
const KUBERNETES_POLICY_ENGINE_DATA_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'k8s_data.json',
);
const TERRAFORM_POLICY_ENGINE_WASM_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'tf_policy.wasm',
);
const TERRAFORM_POLICY_ENGINE_DATA_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'tf_data.json',
);
const CLOUDFORMATION_POLICY_ENGINE_WASM_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'cloudformation_policy.wasm',
);
const CLOUDFORMATION_POLICY_ENGINE_DATA_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'cloudformation_data.json',
);

// NOTE: The filenames used for the custom policy bundles match those output
// by the `opa` CLI tool, which is why they are very generic.
const CUSTOM_POLICY_ENGINE_WASM_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'policy.wasm',
);
const CUSTOM_POLICY_ENGINE_DATA_PATH = path.join(
  LOCAL_POLICY_ENGINE_DIR,
  'data.json',
);

export function assertNever(value: never): never {
  throw new Error(
    `Unhandled discriminated union member: ${JSON.stringify(value)}`,
  );
}

export function getLocalCachePath(engineType: EngineType) {
  switch (engineType) {
    case EngineType.Kubernetes:
      return [
        `${process.cwd()}/${KUBERNETES_POLICY_ENGINE_WASM_PATH}`,
        `${process.cwd()}/${KUBERNETES_POLICY_ENGINE_DATA_PATH}`,
      ];
    case EngineType.Terraform:
      return [
        `${process.cwd()}/${TERRAFORM_POLICY_ENGINE_WASM_PATH}`,
        `${process.cwd()}/${TERRAFORM_POLICY_ENGINE_DATA_PATH}`,
      ];
    case EngineType.CloudFormation:
      return [
        `${process.cwd()}/${CLOUDFORMATION_POLICY_ENGINE_WASM_PATH}`,
        `${process.cwd()}/${CLOUDFORMATION_POLICY_ENGINE_DATA_PATH}`,
      ];
    case EngineType.Custom:
      return [
        `${process.cwd()}/${CUSTOM_POLICY_ENGINE_WASM_PATH}`,
        `${process.cwd()}/${CUSTOM_POLICY_ENGINE_DATA_PATH}`,
      ];
    default:
      assertNever(engineType);
  }
}

function getIacOrgCustomRules(
  publicOrgId?: string,
): Promise<{fileContentResult: string}> {
  const payload: any = {
    method: 'get',
    url: config.API + '/custom-rules',
    json: true,
    qs: { org: publicOrgId },
    headers: {
      // 'x-is-ci': isCI(),
      authorization: `token ${api()}`,
    },
  };

  return new Promise((resolve, reject) => {
    makeRequest(payload, (error, res) => {
      if (error) {
        return reject(error);
      }
      if (res.statusCode < 200 || res.statusCode > 299) {
        return reject(res);
      }
      resolve(res.body);
    });
  });
}


export async function initLocalCache({
  customRulesPath,
}: { customRulesPath?: string } = {}): Promise<void> {
  try {
    createIacDir();
  } catch (e) {
    throw new FailedToInitLocalCacheError();
  }

 
  try {
    console.log('download bundle')
    const response: any = await getIacOrgCustomRules()
    console.log(response.fileContentResult.text)
    // await extractBundle(Readable.from(response.fileContentResult.text))
    // await extractBundle(Readable.from(response.fileContentResult.text))

    // const untar = (buffer): Promise<Buffer[]> => new Promise((resolve, reject) => {

    //   const textData: any[] = [];
    //   const extract = tar.extract();
    //   // Extract method accepts each tarred file as entry, separating header and stream of contents:
    //   extract.on('entry', (header, stream, next) => {
    //     const chunks: any[] = [];
    //     stream.on('data', (chunk) => {
    //       chunks.push(chunk);
    //     });
    //     stream.on('error', (err) => {
    //       reject(err);
    //     });
    //     stream.on('end', () => {
    //       // We concatenate chunks of the stream into string and push it to array, which holds contents of each file in .tar.gz:
    //       const text = Buffer.concat(chunks).toString('utf8');
    //       textData.push(text);
    //       next();
    //     });
    //     stream.resume();
    //   });
    //   extract.on('finish', () => {
    //     // We return array of tarred files's contents:
    //     resolve(textData);
    //   });
    //   // We unzip buffer and convert it to Readable Stream and then pass to tar-stream's extract method:
    //   streamifier.createReadStream(buffer).pipe(extract);

    // })
    // await extractBundle(Readable.from(await untar(response.fileContentResult.text)))
    await extractBundle(Readable.from(response.fileContentResult.text).pipe(zlib.createGunzip()))
  } catch (e) {
    console.log(e)
    throw new FailedToExtractCustomRulesError('blah');
  }
  // // Attempt to extract the custom rules from the path provided.
  // if (customRulesPath) {
  //   try {
  //     const response = fs.createReadStream(customRulesPath);
  //     await extractBundle(response);
  //   } catch (e) {
  //     throw new FailedToExtractCustomRulesError(customRulesPath);
  //   }
  // }

  // We extract the Snyk rules after the custom rules to ensure our files
  // always overwrite whatever might be there.
  try {
    const BUNDLE_URL = 'https://static.snyk.io/cli/wasm/bundle.tar.gz';
    const response: ReadableStream = needle.get(BUNDLE_URL);
    await extractBundle(response);
  } catch (e) {
    throw new FailedToDownloadRulesError();
  }
}

export function cleanLocalCache() {
  // path to delete is hardcoded for now
  const iacPath: fs.PathLike = path.join(`${process.cwd()}`, '.iac-data');
  try {
    // when we support Node version >= 12.10.0 , we can replace rimraf
    // with the native fs.rmdirSync(path, {recursive: true})
    rimraf.sync(iacPath);
  } catch (e) {
    const err = new FailedToCleanLocalCacheError();
    analytics.add('error-code', err.code);
    debug('The local cache directory could not be deleted');
  }
}

export class FailedToInitLocalCacheError extends CustomError {
  constructor(message?: string) {
    super(message || 'Failed to initialize local cache');
    this.code = IaCErrorCodes.FailedToInitLocalCacheError;
    this.strCode = getErrorStringCode(this.code);
    this.userMessage =
      'We were unable to create a local directory to store the test assets, please ensure that the current working directory is writable';
  }
}

export class FailedToDownloadRulesError extends CustomError {
  constructor(message?: string) {
    super(message || 'Failed to download policies');
    this.code = IaCErrorCodes.FailedToDownloadRulesError;
    this.strCode = getErrorStringCode(this.code);
    this.userMessage =
      'We were unable to download the security rules, please ensure the network can access https://static.snyk.io';
  }
}

export class FailedToExtractCustomRulesError extends CustomError {
  constructor(path: string, message?: string) {
    super(message || 'Failed to download policies');
    this.code = IaCErrorCodes.FailedToExtractCustomRulesError;
    this.strCode = getErrorStringCode(this.code);
    this.userMessage = `We were unable to extract the rules provided at: ${path}`;
  }
}

class FailedToCleanLocalCacheError extends CustomError {
  constructor(message?: string) {
    super(message || 'Failed to clean local cache');
    this.code = IaCErrorCodes.FailedToCleanLocalCacheError;
    this.strCode = getErrorStringCode(this.code);
    this.userMessage = ''; // Not a user facing error.
  }
}
