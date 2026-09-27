"""
Stage 3 — Pipeline-stage verifier.

For each repo's import-reachability graph (built by Stage 2; file-level, not a
function-level call graph), determine which of the six MLOps pipeline stages
are present *in reachable code*. A stage is present iff at least one signal
call from its signal list appears in a reachable module. Every hit is
recorded with file + line + matched call, so every label is auditable.

Strict-corpus rule: a repo "passes" only if all six stages are present in the
union of reachable code across all the repo's Dockerfile pipelines.

Signal lists are deliberately broad — covering mainstream Python ML tooling —
but every signal is unambiguous: a single match implies the stage. Library
aliases (`import pandas as panda`) are resolved upstream by Stage 2 so we match
canonical names here.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Signal lists — six pipeline stages.
# ---------------------------------------------------------------------------
# Each entry is a canonical (post-alias) call name. We match on:
#   exact name        : 'pd.read_csv'
#   trailing wildcard : 'tf.keras.layers.*'  (anything starting with that prefix)
#   bare attribute    : '.fit'  (any object's .fit() call — used sparingly)
# Stage rules elsewhere in this file enforce the "single-match suffices" policy.

DATA_ACQUISITION = [
    # pandas / polars / dask / spark / vaex / modin
    "pd.read_csv", "pd.read_parquet", "pd.read_json", "pd.read_excel",
    "pd.read_sql", "pd.read_sql_query", "pd.read_sql_table",
    "pd.read_pickle", "pd.read_hdf", "pd.read_feather", "pd.read_orc",
    "pd.read_html", "pd.read_xml", "pd.read_clipboard",
    "pl.read_csv", "pl.read_parquet", "pl.read_json", "pl.read_excel",
    "pl.scan_csv", "pl.scan_parquet", "pl.read_database",
    "dd.read_csv", "dd.read_parquet", "dd.read_json",
    "spark.read.csv", "spark.read.parquet", "spark.read.json",
    "spark.read.format", "spark.read.load", "spark.read.table",
    "vaex.open", "modin.read_csv",
    # numpy / scipy
    "np.load", "np.loadtxt", "np.genfromtxt", "np.fromfile",
    "scipy.io.loadmat", "scipy.io.wavfile.read", "scipy.io.arff.loadarff",
    "scipy.sparse.load_npz",
    # stdlib
    "csv.reader", "csv.DictReader",
    "json.load", "pickle.load", "yaml.safe_load", "yaml.load",
    "tarfile.open", "zipfile.ZipFile", "gzip.open",
    # web / cloud
    "requests.get", "requests.post", "httpx.get", "httpx.AsyncClient",
    "aiohttp.ClientSession",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "boto3.client", "boto3.resource", "boto3.Session",
    "google.cloud.storage.Client", "google.cloud.bigquery.Client",
    "azure.storage.blob.BlobClient", "azure.storage.blob.BlobServiceClient",
    "gcsfs.GCSFileSystem", "s3fs.S3FileSystem", "fsspec.open",
    "snowflake.connector.connect",
    # ML data hubs
    "datasets.load_dataset", "datasets.load_from_disk",
    "Dataset.from_csv", "Dataset.from_pandas", "Dataset.from_dict",
    "Dataset.from_json", "Dataset.from_parquet",
    "load_dataset", "load_from_disk",
    "tfds.load", "tfds.builder", "tfds.as_numpy",
    "torchvision.datasets.*", "torchaudio.datasets.*", "torchtext.datasets.*",
    "torch_geometric.datasets.*",
    "kaggle.api.dataset_download_files", "kaggle.api.dataset_download_file",
    "kaggle.api.competition_download_files",
    # DBs / DVC / file formats
    "sqlalchemy.create_engine", "sqlite3.connect", "psycopg2.connect",
    "pymongo.MongoClient",
    "dvc.api.read", "dvc.api.open", "dvc.api.get_url",
    "h5py.File", "zarr.open", "zarr.open_array", "zarr.open_group",
    "xarray.open_dataset", "xarray.open_dataarray", "xarray.open_mfdataset",
    "netCDF4.Dataset",
    # media-specific loaders
    "cv2.imread", "cv2.VideoCapture", "cv2.imreadmulti",
    "Image.open", "PIL.Image.open",
    "librosa.load", "soundfile.read", "torchaudio.load",
    "nibabel.load", "pydicom.dcmread", "SimpleITK.ReadImage",
    "rasterio.open", "geopandas.read_file",
    "trimesh.load",
    # PyTorch Lightning data modules — instantiation counts as wiring data in
    "LightningDataModule", "pl.LightningDataModule",
    # Generic DataLoader as the entry to actual reading
    "DataLoader", "torch.utils.data.DataLoader",
]

DATA_PREPARATION = [
    # sklearn splitting / CV
    "train_test_split",
    "KFold", "StratifiedKFold", "GroupKFold", "TimeSeriesSplit",
    "RepeatedKFold", "RepeatedStratifiedKFold", "ShuffleSplit",
    "LeaveOneOut", "LeavePOut",
    # sklearn scaling / encoding / imputation
    "StandardScaler", "MinMaxScaler", "RobustScaler", "Normalizer", "MaxAbsScaler",
    "PowerTransformer", "QuantileTransformer",
    "OneHotEncoder", "LabelEncoder", "OrdinalEncoder", "TargetEncoder",
    "LabelBinarizer", "MultiLabelBinarizer",
    "SimpleImputer", "KNNImputer", "IterativeImputer", "MissingIndicator",
    "ColumnTransformer", "FunctionTransformer",
    "sklearn.pipeline.Pipeline", "Pipeline", "make_pipeline",
    "PolynomialFeatures", "Binarizer", "KBinsDiscretizer",
    "PCA", "TruncatedSVD",  # dim-reduction as a prep step
    # pandas wrangling
    "df.fillna", "df.dropna", "df.drop_duplicates", "df.replace",
    "df.astype", "df.apply", "df.assign", "df.groupby",
    "pd.get_dummies", "pd.cut", "pd.qcut", "pd.merge", "pd.concat",
    "pd.to_datetime", "pd.to_numeric",
    ".melt", ".pivot", ".pivot_table",
    "np.nan_to_num",
    # feature engineering ecosystems
    "featuretools.dfs",
    "tsfresh.extract_features",
    # tokenization / NLP prep
    "Tokenizer", "AutoTokenizer.from_pretrained",
    "BertTokenizer.from_pretrained", "GPT2Tokenizer.from_pretrained",
    "T5Tokenizer.from_pretrained", "RobertaTokenizer.from_pretrained",
    "PreTrainedTokenizer.from_pretrained", "PreTrainedTokenizerFast.from_pretrained",
    "AutoFeatureExtractor.from_pretrained", "AutoProcessor.from_pretrained",
    "AutoImageProcessor.from_pretrained",
    "nltk.tokenize.word_tokenize", "nltk.tokenize.sent_tokenize",
    "nltk.stem.WordNetLemmatizer", "nltk.stem.PorterStemmer",
    "spacy.load", "spacy.blank",
    "sentencepiece.SentencePieceProcessor",
    "tiktoken.encoding_for_model", "tiktoken.get_encoding",
    # image / audio augmentation
    "torchvision.transforms.*", "transforms.Compose",
    "albumentations.*", "A.Compose",
    "audiomentations.*",
    "kornia.augmentation.*",
    "imgaug.augmenters.*",
    # imbalanced learning
    "SMOTE", "RandomOverSampler", "RandomUnderSampler", "ADASYN",
    "BorderlineSMOTE", "SMOTEENN", "SMOTETomek",
    # HuggingFace collation
    "DataCollatorForLanguageModeling", "DataCollatorWithPadding",
    "DataCollatorForSeq2Seq", "DataCollatorForTokenClassification",
    "DataCollatorForWholeWordMask", "DefaultDataCollator",
    # PyTorch Dataset subclassing — instantiating these counts as prep
    "torch.utils.data.Dataset", "torch.utils.data.IterableDataset",
    # Note: .__getitem__ was considered as a Dataset signal but excluded —
    # too generic (every container defines __getitem__).
    # Dataset .map() — pandas/HF transformation patterns
    "Dataset.map", "Dataset.filter", "Dataset.shuffle", "Dataset.train_test_split",
]

MODELING = [
    # PyTorch — module subclassing handled separately (see _find_model_subclasses)
    "nn.Sequential", "nn.Linear", "nn.Conv1d", "nn.Conv2d", "nn.Conv3d",
    "nn.ConvTranspose2d", "nn.ConvTranspose3d",
    "nn.LSTM", "nn.GRU", "nn.RNN", "nn.LSTMCell", "nn.GRUCell",
    "nn.Transformer", "nn.TransformerEncoder", "nn.TransformerDecoder",
    "nn.TransformerEncoderLayer", "nn.TransformerDecoderLayer",
    "nn.MultiheadAttention",
    "nn.BatchNorm1d", "nn.BatchNorm2d", "nn.BatchNorm3d",
    "nn.LayerNorm", "nn.GroupNorm", "nn.InstanceNorm2d",
    "nn.Embedding", "nn.EmbeddingBag",
    "nn.Dropout", "nn.Dropout2d",
    "nn.MaxPool2d", "nn.AvgPool2d", "nn.AdaptiveAvgPool2d",
    "nn.ModuleList", "nn.ModuleDict",
    # TF / Keras
    "keras.Sequential", "tf.keras.Sequential",
    "tf.keras.layers.*", "layers.Dense", "layers.Conv2D", "layers.LSTM",
    "layers.Embedding", "layers.MultiHeadAttention",
    "keras.Model", "tf.keras.Model",
    "keras.layers.*",
    "Model",  # bare Keras Model class instantiation
    # JAX / Flax / Haiku
    "flax.linen.Module", "nn.Module",  # JAX flax.linen uses 'nn' alias commonly
    "hk.Module", "haiku.Module",
    # boosted trees
    "XGBClassifier", "XGBRegressor", "XGBRanker",
    "xgb.XGBClassifier", "xgb.XGBRegressor", "xgb.DMatrix",
    "LGBMClassifier", "LGBMRegressor", "LGBMRanker", "lgb.Dataset",
    "lgb.LGBMClassifier", "lgb.LGBMRegressor",
    "CatBoostClassifier", "CatBoostRegressor", "CatBoostRanker",
    # sklearn classical
    "RandomForestClassifier", "RandomForestRegressor",
    "ExtraTreesClassifier", "ExtraTreesRegressor",
    "GradientBoostingClassifier", "GradientBoostingRegressor",
    "HistGradientBoostingClassifier", "HistGradientBoostingRegressor",
    "AdaBoostClassifier", "AdaBoostRegressor",
    "DecisionTreeClassifier", "DecisionTreeRegressor",
    "LogisticRegression", "LinearRegression",
    "Ridge", "Lasso", "ElasticNet", "BayesianRidge",
    "SVC", "SVR", "LinearSVC", "NuSVC",
    "KMeans", "MiniBatchKMeans", "DBSCAN", "HDBSCAN",
    "AgglomerativeClustering", "SpectralClustering", "GaussianMixture",
    "MLPClassifier", "MLPRegressor",
    "GaussianNB", "MultinomialNB", "BernoulliNB",
    "KNeighborsClassifier", "KNeighborsRegressor",
    # statsmodels
    "statsmodels.api.OLS", "sm.OLS", "sm.Logit", "sm.GLM", "sm.Poisson",
    "OLS", "Logit", "GLM",
    "ARIMA", "SARIMAX", "ExponentialSmoothing",
    # HuggingFace / timm / lightning
    "AutoModel.from_pretrained",
    "AutoModelForSequenceClassification.from_pretrained",
    "AutoModelForCausalLM.from_pretrained",
    "AutoModelForTokenClassification.from_pretrained",
    "AutoModelForQuestionAnswering.from_pretrained",
    "AutoModelForMaskedLM.from_pretrained",
    "AutoModelForSeq2SeqLM.from_pretrained",
    "AutoModelForImageClassification.from_pretrained",
    "AutoModelForObjectDetection.from_pretrained",
    "AutoModelForSemanticSegmentation.from_pretrained",
    "AutoModelForAudioClassification.from_pretrained",
    "AutoModelForVision2Seq.from_pretrained",
    "BertModel.from_pretrained", "GPT2Model.from_pretrained",
    "T5Model.from_pretrained", "RobertaModel.from_pretrained",
    "ViTModel.from_pretrained", "CLIPModel.from_pretrained",
    "timm.create_model", "timm.list_models",
    # Lightning model creation patterns
    "LightningModule", "pl.LightningModule", "lightning.LightningModule",
    # PyG / DGL graph models
    "torch_geometric.nn.*", "dgl.nn.*", "pyg_nn.*",
    # Forecasting
    "Prophet", "prophet.Prophet",
    "darts.models.*", "neuralforecast.models.*",
    # Hydra/configure-then-instantiate pattern — only the qualified form, since
    # `instantiate` alone matches too many unrelated calls.
    "hydra.utils.instantiate",
]

TRAINING = [
    # high-level fits — sklearn / Keras / xgb / lgb
    "model.fit", "model.fit_generator", ".fit_predict", ".partial_fit",
    "estimator.fit", "clf.fit", "regr.fit",
    # trainers (PyTorch Lightning / HuggingFace / Accelerate / Composer)
    "Trainer.train", "Trainer.fit",
    "trainer.train", "trainer.fit",
    "pl.Trainer", "lightning.Trainer",  # Trainer instantiation = training intent
    "SFTTrainer", "DPOTrainer", "RewardTrainer", "PPOTrainer",  # trl
    "Composer.fit",  # mosaicml composer
    # boosted-tree training
    "xgb.train", "lgb.train", "lightgbm.train",
    "CatBoost.fit", "catboost.train",
    # explicit training-loop primitives
    "optimizer.step", "loss.backward", "optimizer.zero_grad",
    "tf.GradientTape",
    "accelerator.backward", "accelerator.prepare",
    "scheduler.step", "lr_scheduler.step",
    "DDP", "DistributedDataParallel",  # distributed training setup
    "deepspeed.initialize", "deepspeed.DeepSpeedEngine",
    "fsdp.FullyShardedDataParallel", "FSDP",
    # Lightning-specific training methods (LightningModule subclasses define these)
    "training_step",
    # hyperparameter search frameworks (do training internally)
    "study.optimize",  # Optuna
    "GridSearchCV", "RandomizedSearchCV", "HalvingGridSearchCV",
    "BayesSearchCV",  # skopt
    "ray.tune.run", "tune.run", "tune.Tuner",
    "wandb.agent",  # W&B sweeps
    # experiment tracking starts (strongly imply training context)
    "mlflow.start_run", "wandb.init", "wandb.watch",
    "neptune.init_run", "neptune.init",
    "comet_ml.Experiment",
    "tensorboard.SummaryWriter", "SummaryWriter",
    # autolog
    "mlflow.autolog", "mlflow.sklearn.autolog", "mlflow.pytorch.autolog",
    "mlflow.tensorflow.autolog", "wandb.sklearn.plot_classifier",
    # Hydra training entry
    "hydra.main",
]

EVALUATION = [
    # sklearn classification metrics
    "accuracy_score", "f1_score", "precision_score", "recall_score",
    "roc_auc_score", "average_precision_score",
    "balanced_accuracy_score", "matthews_corrcoef", "cohen_kappa_score",
    "jaccard_score", "fbeta_score",
    "classification_report", "confusion_matrix",
    "log_loss", "hamming_loss", "zero_one_loss",
    "precision_recall_curve", "roc_curve", "det_curve",
    "precision_recall_fscore_support",
    "multilabel_confusion_matrix",
    # sklearn regression metrics
    "mean_squared_error", "mean_absolute_error", "root_mean_squared_error",
    "mean_squared_log_error", "median_absolute_error",
    "mean_absolute_percentage_error", "r2_score", "explained_variance_score",
    "max_error", "d2_absolute_error_score",
    # clustering metrics
    "silhouette_score", "calinski_harabasz_score", "davies_bouldin_score",
    "adjusted_rand_score", "adjusted_mutual_info_score",
    "normalized_mutual_info_score", "homogeneity_score", "completeness_score",
    "v_measure_score", "fowlkes_mallows_score",
    # ranking
    "ndcg_score", "dcg_score",
    # NLP / generation metrics
    "sacrebleu.compute_bleu", "sacrebleu.corpus_bleu", "sacrebleu.sentence_bleu",
    "corpus_bleu", "sentence_bleu",
    "rouge_score", "rouge_scorer.RougeScorer", "Rouge",
    "meteor_score", "bertscore", "bleurt",
    "evaluate.load",  # HuggingFace evaluate library — load any metric
    # torchmetrics — functional API
    "torchmetrics.functional.*",
    "tmf.accuracy", "tmf.f1_score", "tmf.precision", "tmf.recall",
    # torchmetrics — class-based API (instantiation IS evidence)
    "torchmetrics.Accuracy", "torchmetrics.F1Score",
    "torchmetrics.Precision", "torchmetrics.Recall",
    "torchmetrics.AUROC", "torchmetrics.AveragePrecision",
    "torchmetrics.MeanSquaredError", "torchmetrics.MeanAbsoluteError",
    "torchmetrics.R2Score",
    "torchmetrics.ConfusionMatrix",
    "torchmetrics.BLEUScore", "torchmetrics.ROUGEScore",
    "torchmetrics.classification.*", "torchmetrics.regression.*",
    "torchmetrics.Metric",
    "Accuracy", "F1Score", "AUROC", "Precision", "Recall",  # short names (aliased)
    # torchmetrics workflow — these are too generic on their own to be
    # standalone signals (dict.update, progress_bar.update would match), so
    # they're commented out. torchmetrics class instantiations above are
    # sufficient evidence that the metric pattern is used.
    # ".compute", ".update",
    # Keras metrics in compile / standalone classes
    "keras.metrics.*", "tf.keras.metrics.*",
    # model.evaluate / trainer.evaluate / trainer.test
    "model.evaluate", "Trainer.evaluate", "trainer.evaluate",
    "Trainer.test", "trainer.test",
    "Trainer.predict",  # often used for held-out evaluation
    # cross-val
    "cross_val_score", "cross_validate", "cross_val_predict",
    # Lightning logging — `self.log("val_acc", ...)` etc. — extremely common
    "self.log", "self.log_dict",
    "validation_step", "test_step",   # Lightning hooks define evaluation
    # metric logging
    "mlflow.log_metric", "mlflow.log_metrics",
    "wandb.log", "wandb.summary",
    "neptune.log_metric",
    "comet_ml.log_metric",
    "tb.add_scalar", "writer.add_scalar",  # tensorboard
    # HuggingFace compute_metrics convention
    "compute_metrics",
]

INFERENCE = [
    # standard estimator inference
    "model.predict", "model.predict_proba", "model.predict_classes",
    "model.predict_log_proba",
    "estimator.predict", "clf.predict", "regr.predict", "pipeline.predict",
    # `.transform` deliberately excluded: it's mostly preparation
    # (scaler.transform, encoder.transform), not inference.
    # PyTorch inference idioms
    "torch.no_grad", "torch.inference_mode", "model.eval",
    "module.eval",
    # Lightning inference hooks
    "predict_step",
    "Trainer.predict", "trainer.predict",   # inference invocation
    "Trainer.test", "trainer.test",          # often used in inference/eval contexts
    # exported / accelerated runtimes
    "onnxruntime.InferenceSession",
    "onnx.load",
    "torch.jit.load", "torch.jit.trace", "torch.jit.script",
    "torch.compile",
    "tf.saved_model.load", "tf.lite.Interpreter",
    "torch_tensorrt.compile", "tensorrt.Runtime",
    "openvino.runtime.Core", "ov.Core",
    # HuggingFace inference shortcuts
    "transformers.pipeline", "pipeline",
    "AutoModel.generate", "model.generate",  # text generation = inference
    # `.generate` alone is too broad (random generators, UUID generators); the
    # qualified forms above are sufficient evidence.
    # serving frameworks — endpoint definitions imply inference path
    "FastAPI", "fastapi.FastAPI",
    "Flask", "flask.Flask",
    "gradio.Interface", "gr.Interface", "gradio.Blocks", "gr.Blocks",
    "gradio.ChatInterface", "gr.ChatInterface",
    "streamlit.write", "st.write", "streamlit.run", "st.run",
    "bentoml.Service", "bentoml.api",
    "litserve.LitAPI", "ls.LitAPI",
    "torchserve",
    "ray.serve.deployment", "serve.deployment",
    "modal.Function", "modal.web_endpoint",
    "chainlit.on_message",
    # MLflow serving
    "mlflow.pyfunc.load_model", "mlflow.sklearn.load_model",
    "mlflow.pytorch.load_model", "mlflow.tensorflow.load_model",
    "mlflow.transformers.load_model",
    # Triton / KServe inference clients
    "tritonclient.http.InferenceServerClient",
    "tritonclient.grpc.InferenceServerClient",
]


STAGE_SIGNALS: dict[str, list[str]] = {
    "data_acquisition": DATA_ACQUISITION,
    "data_preparation": DATA_PREPARATION,
    "modeling": MODELING,
    "training": TRAINING,
    "evaluation": EVALUATION,
    "inference": INFERENCE,
}


# ---------------------------------------------------------------------------
# Evidence model
# ---------------------------------------------------------------------------

@dataclass
class StageEvidence:
    """A single matched signal — proof that a stage is present."""
    stage: str            # one of STAGE_SIGNALS keys
    matched_signal: str   # the signal pattern that matched ('pd.read_csv', etc.)
    call_name: str        # the actual call as seen in code (post-alias resolution)
    rel_path: str         # file relative to repo root
    line: int             # source line of the call


@dataclass
class StageReport:
    """Per-repo stage verification result."""
    present: dict[str, bool] = field(default_factory=dict)
    evidence: dict[str, StageEvidence] = field(default_factory=dict)
    # evidence_files: stage -> set of repo-relative posix paths where that stage's
    # signals matched anywhere in the file. Stage 4 uses this for fine-grained
    # finding attribution; Stage 1-3 doesn't read it.
    evidence_files: dict[str, set[str]] = field(default_factory=dict)
    extra_module_classes: list[str] = field(default_factory=list)  # Modeling via subclassing

    @property
    def all_six_present(self) -> bool:
        return all(self.present.get(s, False) for s in STAGE_SIGNALS)

    @property
    def present_count(self) -> int:
        return sum(1 for v in self.present.values() if v)


# ---------------------------------------------------------------------------
# Signal matching
# ---------------------------------------------------------------------------

def _match_signal(call_name: str, signal: str) -> bool:
    """Return True iff `call_name` matches `signal`.

    Forms supported:
      'pd.read_csv'        → exact, or any dotted suffix ending in '.pd.read_csv'
                             OR any path ending in '.read_csv' when signal is short
      'tf.keras.layers.*'  → prefix match
      '.fit'               → trailing-attribute match
    The "ends-with" relaxation matters because alias resolution may yield a
    fully-qualified name like 'sklearn.model_selection.train_test_split' even
    when our signal list has the short canonical form 'train_test_split'.
    """
    if signal.endswith(".*"):
        return call_name.startswith(signal[:-2] + ".")
    if signal.startswith("."):
        return call_name.endswith(signal) or call_name == signal[1:]
    if call_name == signal:
        return True
    # Allow short signal to match a fully-qualified call (or vice versa) by
    # the *last segment*. e.g. signal 'train_test_split' should match
    # call 'sklearn.model_selection.train_test_split'. Conversely, a signal
    # like 'pd.read_csv' should match a fully-qualified 'pandas.read_csv'
    # only if the canonical-alias rewrite did not already do so — but to
    # stay safe and simple, we match any call whose dotted tail equals the
    # whole signal.
    return call_name.endswith("." + signal)


def _first_match(call_name: str, signals: Iterable[str]) -> str | None:
    """Return the signal pattern that matched, or None."""
    for s in signals:
        if _match_signal(call_name, s):
            return s
    return None


# ---------------------------------------------------------------------------
# Lightning hook methods (stage evidence via method definition)
# ---------------------------------------------------------------------------
# Defining these methods in a LightningModule subclass is the canonical way to
# declare that the pipeline performs that stage — they're hooks Lightning calls,
# not user calls. They appear in the AST as FunctionDef, not Call. We detect
# them by name in reachable files.

_LIGHTNING_HOOKS: dict[str, str] = {
    "training_step": "training",
    "validation_step": "evaluation",
    "test_step": "evaluation",
    "predict_step": "inference",
    "configure_optimizers": "training",   # only Lightning training defines this
    "train_dataloader": "data_acquisition",
    "val_dataloader": "data_acquisition",
    "test_dataloader": "data_acquisition",
    "predict_dataloader": "data_acquisition",
    "prepare_data": "data_acquisition",   # Lightning data prep hook
    # 'setup' deliberately excluded: too generic — many unrelated classes
    # define a setup() method (Django views, unittest, plugins, etc.).
}


def _find_lightning_hooks(file_path: str) -> list[tuple[str, str, int]]:
    """Return [(hook_name, stage, line)] for Lightning hook methods defined in file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read(), filename=file_path)
    except (OSError, SyntaxError):
        return []
    hits: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stage = _LIGHTNING_HOOKS.get(node.name)
            if stage:
                hits.append((node.name, stage, getattr(node, "lineno", 0)))
    return hits


# ---------------------------------------------------------------------------
# Modeling via class subclassing (special case)
# ---------------------------------------------------------------------------
# Subclassing nn.Module / tf.keras.Model / LightningModule is *the* canonical
# way to define a model and doesn't appear as a "call" in the AST. We detect it
# by inspecting ClassDef nodes in reachable files.

_MODEL_BASE_CLASSES = {
    "nn.Module", "torch.nn.Module", "Module",
    "tf.keras.Model", "keras.Model", "Model",
    "LightningModule", "pl.LightningModule", "lightning.LightningModule",
    "BaseEstimator",  # sklearn custom estimators
}


def _find_model_subclasses(file_path: str) -> list[str]:
    """Return the names of classes in this file that subclass a known model base."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read(), filename=file_path)
    except (OSError, SyntaxError):
        return []

    matches: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            base_name = _name_from_attribute(base)
            if base_name and (base_name in _MODEL_BASE_CLASSES or
                              base_name.endswith(".Module") or
                              base_name.endswith(".Model") or
                              base_name.endswith(".LightningModule")):
                matches.append(node.name)
                break
    return matches


def _name_from_attribute(node: ast.AST) -> str | None:
    """Build a dotted name from an Attribute/Name node (e.g. ast.Attribute -> 'nn.Module')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_from_attribute(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


# ---------------------------------------------------------------------------
# Public API — verify one repo's call graph
# ---------------------------------------------------------------------------

def verify_stages(call_graphs: list, repo_root: str) -> StageReport:
    """Walk the union of reachable code across one or more call graphs and
    determine which of the six pipeline stages are present.

    `call_graphs` is a list of CallGraph objects (one per Dockerfile). We union
    their modules so a repo with separate train.py / serve.py Dockerfiles gets
    credit across both.

    Records two parallel views of the evidence:
      - `present` + `evidence`: first-match per stage (used by Stage 1-3 to
        produce verified_corpus.csv with one example per stage)
      - `evidence_files`: full set of files where each stage matched anywhere
        (used by Stage 4 to attribute findings to stages with fine granularity)
    """
    report = StageReport(present={s: False for s in STAGE_SIGNALS})
    # initialize all six stage buckets to empty sets so callers can iterate safely
    for s in STAGE_SIGNALS:
        report.evidence_files[s] = set()

    # Union of reachable files across all call graphs in this repo.
    union: dict[str, object] = {}
    for cg in call_graphs:
        for path, mod in cg.modules.items():
            union[path] = mod

    # Walk every reachable file. For `present`/`evidence`, keep the first-match
    # short-circuit (Stage 1-3 only needs one example). For `evidence_files`,
    # record every file that contains any signal for each stage.
    for path, mod in union.items():
        rel = os.path.relpath(path, repo_root).replace(os.sep, "/")

        # Modeling-via-subclass — applies to whole file
        subs = _find_model_subclasses(path)
        if subs:
            report.evidence_files["modeling"].add(rel)
            if not report.present["modeling"]:
                report.present["modeling"] = True
                report.evidence["modeling"] = StageEvidence(
                    stage="modeling",
                    matched_signal="<class subclasses model base>",
                    call_name=f"class {subs[0]}",
                    rel_path=rel, line=0,
                )
                report.extra_module_classes.extend(subs)

        # Lightning hook method definitions
        hooks = _find_lightning_hooks(path)
        for hook_name, stage, line in hooks:
            report.evidence_files[stage].add(rel)
            if not report.present[stage]:
                report.present[stage] = True
                report.evidence[stage] = StageEvidence(
                    stage=stage,
                    matched_signal=f"<lightning hook {hook_name}>",
                    call_name=f"def {hook_name}",
                    rel_path=rel, line=line,
                )

        # Per-call signal matching. For each call, check every stage; record
        # the file in evidence_files for every stage that matches.
        seen_stages_this_file: set[str] = set()
        for raw in getattr(mod, "calls", []):
            name, line = _split_call_entry(raw)
            for stage, signals in STAGE_SIGNALS.items():
                if stage in seen_stages_this_file:
                    continue  # already credited this file for this stage
                sig = _first_match(name, signals)
                if sig is not None:
                    seen_stages_this_file.add(stage)
                    report.evidence_files[stage].add(rel)
                    if not report.present[stage]:
                        report.present[stage] = True
                        report.evidence[stage] = StageEvidence(
                            stage=stage, matched_signal=sig, call_name=name,
                            rel_path=rel, line=line,
                        )
            # NOTE: no short-circuit anymore — we keep walking calls so
            # evidence_files captures every stage hit in this file.

    return report


def _split_call_entry(entry: str) -> tuple[str, int]:
    """Parse an enriched call entry 'name@line' (or plain 'name')."""
    if "@" in entry:
        name, _, lineno = entry.rpartition("@")
        try:
            return name, int(lineno)
        except ValueError:
            return entry, 0
    return entry, 0
